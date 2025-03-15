package org.apache.hive.service.auth.ldap;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.security.SaslRpcServer;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.AuthorizeCallback;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class LdapGroupCallbackHandler implements CallbackHandler {
  private static final Logger LOG = LoggerFactory.getLogger(LdapGroupCallbackHandler.class);
  private final HiveConf conf;
  private final boolean enableLdapGroupCheck;
  private final boolean allowCustomLdapFilters;
  private final CallbackHandler delegateHandler;

  public LdapGroupCallbackHandler(HiveConf conf) {
    this.conf = conf;
    this.enableLdapGroupCheck = HiveConf.getBoolVar(
        conf, HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS);
    this.allowCustomLdapFilters = HiveConf.getBoolVar(
        conf, HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH);
    this.delegateHandler = new SaslRpcServer.SaslGssCallbackHandler();
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    List<Callback> unhandledCallbacks = new ArrayList<>();

    for (Callback callback : callbacks) {
      if (callback instanceof AuthorizeCallback) {
        AuthorizeCallback ac = (AuthorizeCallback) callback;
        String authenticationID = ac.getAuthenticationID();
        String authorizationID = ac.getAuthorizationID();

        // Handle delegation case - if authentication ID != authorization ID,
        // delegate to the underlying handler for processing
        if (!authenticationID.equals(authorizationID)) {
          LOG.debug("Delegating authorization for different auth IDs: {} -> {}", 
              authenticationID, authorizationID);
          unhandledCallbacks.add(callback);
          continue;
        }

        // If neither LDAP group check nor custom filter is enabled, authorize immediately.
        if (!enableLdapGroupCheck && !allowCustomLdapFilters) {
          ac.setAuthorized(true);
          continue;
        }
        
        // Check if this is a proxy user - we don't apply LDAP filters to proxy users
        String proxyUser = org.apache.hive.service.cli.session.SessionManager.getProxyUserName();
        if (proxyUser != null && !proxyUser.isEmpty()) {
          LOG.debug("Skipping LDAP filters for proxy user authorization: {}", proxyUser);
          ac.setAuthorized(true);
          continue;
        }

        String user = extractUserName(authenticationID);
        boolean passedGroupCheck = !enableLdapGroupCheck;
        boolean passedCustomFilter = !allowCustomLdapFilters;

        try {
          String bindDN = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER);
          String bindPassword = null;
          try {
            char[] rawPassword = conf.getPassword(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD.toString());
            if (rawPassword != null) {
              bindPassword = new String(rawPassword);
            }
          } catch (IOException ignored) {
          }
          if (bindDN == null || bindDN.isEmpty() || bindPassword == null || bindPassword.isEmpty()) {
            LOG.error("LDAP bind DN or password is not configured.");
            ac.setAuthorized(false);
            continue;
          }

          DirSearchFactory dirSearchFactory = new LdapSearchFactory();
          DirSearch dirSearch = dirSearchFactory.getInstance(conf, bindDN, bindPassword);

          // Apply the LDAP group filter if enabled.
          if (enableLdapGroupCheck) {
            FilterFactory filterFactory = new UserGroupSearchFilterFactory();
            Filter groupFilter = filterFactory.getInstance(conf);
            if (groupFilter == null) {
              groupFilter = new GroupFilterFactory().getInstance(conf);
            }
            if (groupFilter == null) {
              LOG.warn("No LDAP group filter configured. Access denied for user {}", user);
              ac.setAuthorized(false);
              continue;
            }
            try {
              groupFilter.apply(dirSearch, user);
              passedGroupCheck = true;
            } catch (AuthenticationException e) {
              LOG.warn("User {} failed LDAP group check: {}", user, e.getMessage());
            }
          }

          // Apply the custom LDAP filter if enabled.
          if (allowCustomLdapFilters) {
            FilterFactory customFilterFactory = new CustomQueryFilterFactory();
            Filter customFilter = customFilterFactory.getInstance(conf);
            if (customFilter != null) {
              try {
                customFilter.apply(dirSearch, user);
                passedCustomFilter = true;
                LOG.debug("User {} passed the custom LDAP filter.", user);
              } catch (AuthenticationException ae) {
                LOG.warn("User {} failed the custom LDAP filter: {}", user, ae.getMessage());
              }
            } else {
              LOG.warn("Custom LDAP filter is not configured. Skipping custom filter for user {}", user);
              passedCustomFilter = true;
            }
          }
        } catch (AuthenticationException e) {
          LOG.warn("User {} encountered LDAP authentication error: {}", user, e.getMessage());
          ac.setAuthorized(false);
          throw new IOException("LDAP authentication failed.", e);
        }

        ac.setAuthorized(passedGroupCheck && passedCustomFilter);
      } else {
        unhandledCallbacks.add(callback);
      }
    }

    if (!unhandledCallbacks.isEmpty()) {
      delegateHandler.handle(unhandledCallbacks.toArray(new Callback[0]));
    }
  }

  private String extractUserName(@NotNull String principal) {
    int idx = principal.indexOf('@');
    if (idx > 0) {
      principal = principal.substring(0, idx);
    }
    idx = principal.indexOf('/');
    if (idx > 0) {
      principal = principal.substring(0, idx);
    }
    return principal;
  }
}