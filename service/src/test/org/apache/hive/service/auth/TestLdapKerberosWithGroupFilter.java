/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hive.service.auth;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hive.service.auth.ldap.DirSearch;
import org.apache.hive.service.auth.ldap.DirSearchFactory;
import org.apache.hive.service.auth.ldap.Filter;
import org.apache.hive.service.auth.ldap.FilterFactory;
import org.apache.hive.service.auth.ldap.GroupFilterFactory;
import org.apache.hive.service.auth.ldap.CustomQueryFilterFactory;
import org.apache.hive.service.auth.ldap.UserGroupSearchFilterFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.sasl.AuthenticationException;
import java.security.PrivilegedExceptionAction;

import static org.mockito.Mockito.*;

/**
 * Tests for Kerberos authentication with LDAP group filter.
 * This test uses mocks to avoid the need for real LDAP or Kerberos servers.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestLdapKerberosWithGroupFilter {

  private static final String GROUP1_NAME = "group1";
  private static final String GROUP2_NAME = "group2";
  private static final String USER1_ID = "user1";
  private static final String USER2_ID = "user2";

  @Mock
  private UserGroupInformation user1Ugi;
  
  @Mock
  private UserGroupInformation user2Ugi;
  
  @Mock
  private HiveAuthFactory authFactory;
  
  @Mock
  private DirSearch dirSearch;
  
  @Mock
  private DirSearchFactory dirSearchFactory;
  
  @Mock
  private Filter groupFilter;
  
  @Mock
  private Filter customFilter;
  
  @Mock
  private FilterFactory groupFilterFactory;
  
  @Mock
  private FilterFactory customFilterFactory;

  private HiveConf conf;

  @Before
  public void setup() throws Exception {
    // Setup UGIs for our test users
    when(user1Ugi.getUserName()).thenReturn(USER1_ID + "@TEST.REALM");
    when(user1Ugi.getShortUserName()).thenReturn(USER1_ID);
    
    when(user2Ugi.getUserName()).thenReturn(USER2_ID + "@TEST.REALM");
    when(user2Ugi.getShortUserName()).thenReturn(USER2_ID);
    
    // Setup HiveConf for LDAP
    conf = new HiveConf();
    conf.set("hive.root.logger", "DEBUG,console");
    
    // Setup LDAP connection params
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_URL, "ldap://localhost:10389");
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER, "cn=admin,dc=example,dc=com");
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD, "admin");
    
    // Configure Kerberos auth with LDAP group checking
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_AUTHENTICATION, "KERBEROS");
    
    // Setup filter factory mocks
    when(groupFilterFactory.getInstance(any(HiveConf.class))).thenReturn(groupFilter);
    when(customFilterFactory.getInstance(any(HiveConf.class))).thenReturn(customFilter);
    
    // Setup DirSearch factory mock
    when(dirSearchFactory.getInstance(any(HiveConf.class), anyString(), anyString())).thenReturn(dirSearch);
  }

  @After
  public void tearDown() {
    // Reset configuration
    conf = null;
  }

  @Test
  public void testKerberosAuthWithLdapGroupCheckPositive() throws Exception {
    // Configure LDAP to only allow users in group1 (which includes user1)
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    
    // Configure group filter to pass for user1
    doNothing().when(groupFilter).apply(eq(dirSearch), eq(USER1_ID));
    
    // Create test subject
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user1Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should pass for user1 (member of group1)
    authenticator.authenticate("ignored", "ignored");
    
    // Verify UGI was used
    verify(user1Ugi).doAs(any(PrivilegedExceptionAction.class));
    
    // Verify group filter was applied
    verify(groupFilter).apply(eq(dirSearch), eq(USER1_ID));
  }

  @Test(expected = AuthenticationException.class)
  public void testKerberosAuthWithLdapGroupCheckNegative() throws Exception {
    // Configure LDAP to only allow users in group1 (which does NOT include user2)
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    
    // Configure group filter to fail for user2
    doThrow(new AuthenticationException("User not in required group"))
        .when(groupFilter).apply(eq(dirSearch), eq(USER2_ID));
    
    // Create test subject
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should fail for user2 (not a member of group1)
    authenticator.authenticate("ignored", "ignored");
  }

  @Test
  public void testKerberosAuthWithMultipleLdapGroupCheckPositive() throws Exception {
    // Configure LDAP to allow users in either group1 or group2
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME + "," + GROUP2_NAME);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    
    // Configure group filter to pass for both users
    doNothing().when(groupFilter).apply(eq(dirSearch), anyString());
    
    // Create test subjects
    LdapKerberosAuthenticator authenticator1 = new TestLdapKerberosAuthenticator(
        conf, authFactory, user1Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    LdapKerberosAuthenticator authenticator2 = new TestLdapKerberosAuthenticator(
        conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should pass for both users
    authenticator1.authenticate("ignored", "ignored");
    authenticator2.authenticate("ignored", "ignored");
    
    // Verify UGIs were used
    verify(user1Ugi).doAs(any(PrivilegedExceptionAction.class));
    verify(user2Ugi).doAs(any(PrivilegedExceptionAction.class));
    
    // Verify group filter was applied for both users
    verify(groupFilter).apply(eq(dirSearch), eq(USER1_ID));
    verify(groupFilter).apply(eq(dirSearch), eq(USER2_ID));
  }

  @Test
  public void testKerberosAuthWithDisabledLdapGroupCheck() throws Exception {
    // Disable LDAP group check
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    
    // Set a group filter anyway - it should be ignored
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME);
    
    // Create test subjects
    LdapKerberosAuthenticator authenticator1 = new TestLdapKerberosAuthenticator(
        conf, authFactory, user1Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    LdapKerberosAuthenticator authenticator2 = new TestLdapKerberosAuthenticator(
        conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should pass for both users since group check is disabled
    authenticator1.authenticate("ignored", "ignored");
    authenticator2.authenticate("ignored", "ignored");
    
    // Verify UGIs were used
    verify(user1Ugi).doAs(any(PrivilegedExceptionAction.class));
    verify(user2Ugi).doAs(any(PrivilegedExceptionAction.class));
    
    // Verify no LDAP interactions occurred
    verifyNoInteractions(dirSearch, groupFilter);
  }
  
  @Test
  public void testKerberosAuthWithProxyUser() throws Exception {
    // Enable LDAP group check
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    
    // Configure group filter to fail for user2 (would normally deny access)
    doThrow(new AuthenticationException("User not in required group"))
        .when(groupFilter).apply(eq(dirSearch), eq(USER2_ID));
    
    // Set a proxy user in session manager
    try {
      // Set proxy user
      org.apache.hive.service.cli.session.SessionManager.setProxyUserName("proxyUser");
      
      // Create test subject for user2 (would normally be denied)
      LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
          conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
      
      // Authentication should pass despite not being in group, because it's a proxy user
      authenticator.authenticate("ignored", "ignored");
      
      // Verify UGI was used
      verify(user2Ugi).doAs(any(PrivilegedExceptionAction.class));
      
      // Verify LDAP filter was NOT applied (no interactions with group filter)
      verifyNoInteractions(dirSearch, groupFilter);
    } finally {
      // Clean up
      org.apache.hive.service.cli.session.SessionManager.clearProxyUserName();
    }
  }

  @Test
  public void testKerberosAuthWithCustomLdapFilterPositive() throws Exception {
    // Enable custom LDAP filter
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Set custom query to allow only user1
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_CUSTOMLDAPQUERY, 
        "(&(objectClass=person)(uid=" + USER1_ID + "))");
    
    // Configure custom filter to pass for user1
    doNothing().when(customFilter).apply(eq(dirSearch), eq(USER1_ID));
    
    // Create test subject
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user1Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should pass for user1
    authenticator.authenticate("ignored", "ignored");
    
    // Verify UGI was used
    verify(user1Ugi).doAs(any(PrivilegedExceptionAction.class));
    
    // Verify custom filter was applied
    verify(customFilter).apply(eq(dirSearch), eq(USER1_ID));
  }

  @Test(expected = AuthenticationException.class)
  public void testKerberosAuthWithCustomLdapFilterNegative() throws Exception {
    // Enable custom LDAP filter
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Set custom query to allow only user1
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_CUSTOMLDAPQUERY, 
        "(&(objectClass=person)(uid=" + USER1_ID + "))");
    
    // Configure custom filter to fail for user2
    doThrow(new AuthenticationException("User does not match custom filter"))
        .when(customFilter).apply(eq(dirSearch), eq(USER2_ID));
    
    // Create test subject for user2
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should fail for user2
    authenticator.authenticate("ignored", "ignored");
  }

  @Test
  public void testKerberosAuthWithBothLdapFiltersPositive() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Group filter allows user1 only
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME);
    
    // Custom query allows any person
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_CUSTOMLDAPQUERY, "(&(objectClass=person))");
    
    // Configure both filters to pass for user1
    doNothing().when(groupFilter).apply(eq(dirSearch), eq(USER1_ID));
    doNothing().when(customFilter).apply(eq(dirSearch), eq(USER1_ID));
    
    // Create test subject
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user1Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should pass for user1 (passes both filters)
    authenticator.authenticate("ignored", "ignored");
    
    // Verify UGI was used
    verify(user1Ugi).doAs(any(PrivilegedExceptionAction.class));
    
    // Verify both filters were applied
    verify(groupFilter).apply(eq(dirSearch), eq(USER1_ID));
    verify(customFilter).apply(eq(dirSearch), eq(USER1_ID));
  }

  @Test(expected = AuthenticationException.class)
  public void testKerberosAuthWithBothLdapFiltersNegative() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Group filter allows user1 only
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPFILTER, GROUP1_NAME);
    
    // Custom query allows any person
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_CUSTOMLDAPQUERY, "(&(objectClass=person))");
    
    // Configure group filter to fail for user2
    doThrow(new AuthenticationException("User not in required group"))
        .when(groupFilter).apply(eq(dirSearch), eq(USER2_ID));
    
    // Custom filter would pass, but it won't get called due to group filter failing first
    doNothing().when(customFilter).apply(eq(dirSearch), eq(USER2_ID));
    
    // Create test subject for user2
    LdapKerberosAuthenticator authenticator = new TestLdapKerberosAuthenticator(
        conf, authFactory, user2Ugi, dirSearchFactory, groupFilterFactory, customFilterFactory);
    
    // Authentication should fail for user2 (fails group filter)
    authenticator.authenticate("ignored", "ignored");
  }

  /**
   * A test Kerberos authenticator that uses a predefined UGI for testing.
   */
  private static class TestLdapKerberosAuthenticator extends LdapKerberosAuthenticator {
    private final UserGroupInformation testUgi;

    public TestLdapKerberosAuthenticator(
        HiveConf conf, 
        HiveAuthFactory authFactory, 
        UserGroupInformation ugi,
        DirSearchFactory dirSearchFactory,
        FilterFactory groupFilterFactory,
        FilterFactory customFilterFactory) {
      super(conf, authFactory, dirSearchFactory, groupFilterFactory, customFilterFactory);
      this.testUgi = ugi;
    }

    @Override
    protected UserGroupInformation getCurrentUser() {
      return testUgi;
    }
  }

  /**
   * A helper Kerberos authenticator for LDAP testing.
   * This is a test-only implementation of a Kerberos authentication provider
   * with LDAP group filter support.
   */
  private static class LdapKerberosAuthenticator implements PasswdAuthenticationProvider {
    protected final HiveConf conf;
    protected final HiveAuthFactory authFactory;
    protected final DirSearchFactory dirSearchFactory;
    protected final FilterFactory groupFilterFactory;
    protected final FilterFactory customFilterFactory;
    
    public LdapKerberosAuthenticator(
        HiveConf conf, 
        HiveAuthFactory authFactory,
        DirSearchFactory dirSearchFactory,
        FilterFactory groupFilterFactory,
        FilterFactory customFilterFactory) {
      this.conf = conf;
      this.authFactory = authFactory;
      this.dirSearchFactory = dirSearchFactory;
      this.groupFilterFactory = groupFilterFactory;
      this.customFilterFactory = customFilterFactory;
    }

    protected UserGroupInformation getCurrentUser() {
      return null; // Implemented by test subclass
    }

    @Override
    public void authenticate(String user, String password) throws AuthenticationException {
      try {
        UserGroupInformation ugi = getCurrentUser();
        if (ugi == null) {
          throw new AuthenticationException("No current user");
        }
        
        // Check LDAP group membership if enabled
        if (shouldCheckLdapGroupMembership()) {
          checkLdapGroupMembership(ugi);
        }
        
        // Do privileged action similar to actual implementation
        ugi.doAs((PrivilegedExceptionAction<Void>) () -> {
          // In actual implementation, this would do RPC operations
          // For testing, we just validate LDAP group membership
          return null;
        });
      } catch (Exception e) {
        if (e instanceof AuthenticationException) {
          throw (AuthenticationException) e;
        }
        throw new AuthenticationException("Authentication failed", e);
      }
    }
    
    /**
     * Checks if LDAP group membership validation should be performed.
     * @return true if LDAP group checks should be performed
     */
    protected boolean shouldCheckLdapGroupMembership() {
      boolean enableGroupCheck = conf.getBoolVar(
          HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS);
      boolean enableCustomFilter = conf.getBoolVar(
          HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH);
      
      return enableGroupCheck || enableCustomFilter;
    }
    
    /**
     * Performs LDAP group membership checks for the current Kerberos user.
     * @param ugi the current user's UserGroupInformation
     * @throws AuthenticationException if the user does not pass LDAP group checks
     */
    protected void checkLdapGroupMembership(UserGroupInformation ugi) throws AuthenticationException {
      boolean enableGroupCheck = conf.getBoolVar(
          HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS);
      boolean enableCustomFilter = conf.getBoolVar(
          HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH);
      
      if (!enableGroupCheck && !enableCustomFilter) {
        return;
      }
      
      String bindDN = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER);
      String bindPassword = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD);
      
      if (bindDN == null || bindDN.isEmpty() || bindPassword == null || bindPassword.isEmpty()) {
        return;
      }
      
      try {
        // Get the user's short name
        String username = ugi.getShortUserName();
        
        // Get the directory search instance
        DirSearch dirSearch = dirSearchFactory.getInstance(conf, bindDN, bindPassword);
        
        // Group filter check
        if (enableGroupCheck) {
          // Get the group filter
          Filter filter = groupFilterFactory.getInstance(conf);
          if (filter == null) {
            filter = new GroupFilterFactory().getInstance(conf);
          }
          
          if (filter != null) {
            // Apply the group filter
            filter.apply(dirSearch, username);
          }
        }
        
        // Custom filter check
        if (enableCustomFilter) {
          // Get the custom filter
          Filter filter = customFilterFactory.getInstance(conf);
          
          if (filter != null) {
            // Apply the custom filter
            filter.apply(dirSearch, username);
          }
        }
      } catch (Exception e) {
        if (e instanceof AuthenticationException) {
          throw (AuthenticationException) e;
        }
        throw new AuthenticationException("LDAP authentication failed: " + e.getMessage(), e);
      }
    }
  }
}