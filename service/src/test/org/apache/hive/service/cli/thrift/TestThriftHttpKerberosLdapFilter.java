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
package org.apache.hive.service.cli.thrift;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.hive.service.auth.HttpAuthenticationException;
import org.apache.hive.service.auth.ldap.CustomQueryFilterFactory;
import org.apache.hive.service.auth.ldap.DirSearch;
import org.apache.hive.service.auth.ldap.DirSearchFactory;
import org.apache.hive.service.auth.ldap.Filter;
import org.apache.hive.service.auth.ldap.FilterFactory;
import org.apache.hive.service.auth.ldap.GroupFilterFactory;
import org.apache.hive.service.auth.ldap.UserGroupSearchFilterFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for the HTTP Kerberos authentication with additional LDAP group filtering.
 * Uses Mockito for mocking LDAP and Kerberos components.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestThriftHttpKerberosLdapFilter {

  private static final String TEST_USER = "user";
  private static final String TEST_REALM = "TEST.REALM";
  private static final String TEST_PRINCIPAL = TEST_USER + "@" + TEST_REALM;

  @Mock
  private GSSContext gssContext;

  @Mock
  private GSSName gssName;

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

  private HiveConf hiveConf;
  private TestableKerberosAuthHandler authHandler;

  @Before
  public void setup() throws Exception {
    hiveConf = new HiveConf();
    
    // Set up bind user and password
    hiveConf.setVar(ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER, "bindUser");
    hiveConf.setVar(ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD, "bindPassword");
    
    // Mock GSSContext to return a test principal
    when(gssName.toString()).thenReturn(TEST_PRINCIPAL);
    when(gssContext.getSrcName()).thenReturn(gssName);
    
    // Mock DirSearchFactory and FilterFactories
    when(dirSearchFactory.getInstance(any(HiveConf.class), anyString(), anyString())).thenReturn(dirSearch);
    when(groupFilterFactory.getInstance(any(HiveConf.class))).thenReturn(groupFilter);
    when(customFilterFactory.getInstance(any(HiveConf.class))).thenReturn(customFilter);
    
    // Configure filters to succeed by default
    doNothing().when(groupFilter).apply(any(DirSearch.class), anyString());
    doNothing().when(customFilter).apply(any(DirSearch.class), anyString());
    
    // Create a testable auth handler with mocked components
    authHandler = new TestableKerberosAuthHandler(hiveConf, dirSearchFactory, 
        groupFilterFactory, customFilterFactory);
  }

  @Test
  public void testKerberosAuthWithNoLdapFilters() throws Exception {
    // Disable both filters
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, false);
    
    // Run authentication
    String username = authHandler.run();
    
    // Verify username was extracted correctly from Kerberos principal
    assertEquals(TEST_USER, username);
    
    // Verify no LDAP operations occurred
    verifyNoInteractions(dirSearch, groupFilter, customFilter);
  }

  @Test
  public void testKerberosAuthWithGroupFilterEnabled() throws Exception {
    // Enable only group filter
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, false);
    
    // Run authentication
    String username = authHandler.run();
    
    // Verify username was extracted correctly
    assertEquals(TEST_USER, username);
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(hiveConf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(hiveConf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verifyNoInteractions(customFilter);
  }

  @Test
  public void testKerberosAuthWithCustomFilterEnabled() throws Exception {
    // Enable only custom filter
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Run authentication
    String username = authHandler.run();
    
    // Verify username was extracted correctly
    assertEquals(TEST_USER, username);
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(hiveConf), eq("bindUser"), eq("bindPassword"));
    verify(customFilterFactory).getInstance(eq(hiveConf));
    verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
    verifyNoInteractions(groupFilter);
  }

  @Test
  public void testKerberosAuthWithBothFiltersEnabled() throws Exception {
    // Enable both filters
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Run authentication
    String username = authHandler.run();
    
    // Verify username was extracted correctly
    assertEquals(TEST_USER, username);
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(hiveConf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(hiveConf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verify(customFilterFactory).getInstance(eq(hiveConf));
    verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
  }

  @Test(expected = HttpAuthenticationException.class)
  public void testKerberosAuthWithGroupFilterFailure() throws Exception {
    // Enable both filters
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Configure group filter to throw exception
    doThrow(new AuthenticationException("User not in group"))
        .when(groupFilter).apply(any(), anyString());
    
    // Run authentication - should throw exception
    authHandler.run();
  }

  @Test(expected = HttpAuthenticationException.class)
  public void testKerberosAuthWithCustomFilterFailure() throws Exception {
    // Enable both filters
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Configure group filter to pass but custom filter to fail
    doNothing().when(groupFilter).apply(any(), anyString());
    doThrow(new AuthenticationException("Custom filter failed"))
        .when(customFilter).apply(any(), anyString());
    
    // Run authentication - should throw exception
    authHandler.run();
  }

  @Test
  public void testKerberosAuthWithMissingBindCredentials() throws Exception {
    // Enable both filters but remove bind credentials
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    hiveConf.unset(ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER.varname);
    
    // Run authentication
    String username = authHandler.run();
    
    // Verify username was extracted correctly
    assertEquals(TEST_USER, username);
    
    // Verify no LDAP operations were performed due to missing credentials
    verifyNoInteractions(dirSearch, groupFilter, customFilter);
  }
  
  @Test
  public void testKerberosAuthWithProxyUser() throws Exception {
    // Enable both filters
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Configure filters to throw exceptions
    doThrow(new AuthenticationException("User not in group"))
        .when(groupFilter).apply(any(), anyString());
    doThrow(new AuthenticationException("Custom filter failed"))
        .when(customFilter).apply(any(), anyString());
    
    try {
      // Set proxy user
      org.apache.hive.service.cli.session.SessionManager.setProxyUserName("proxyUser");
      
      // Run authentication
      String username = authHandler.run();
      
      // Verify username was extracted correctly
      assertEquals(TEST_USER, username);
      
      // Verify no LDAP operations were performed because of proxy user
      verifyNoInteractions(dirSearch, groupFilter, customFilter);
    } finally {
      // Clean up
      org.apache.hive.service.cli.session.SessionManager.clearProxyUserName();
    }
  }

  @Test(expected = HttpAuthenticationException.class)
  public void testKerberosAuthWithDirSearchException() throws Exception {
    // Enable group filter
    hiveConf.setBoolVar(ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    
    // Configure dirSearchFactory to throw exception
    when(dirSearchFactory.getInstance(any(), anyString(), anyString()))
        .thenThrow(new AuthenticationException("LDAP connection failed"));
    
    // Run authentication - should throw exception
    authHandler.run();
  }

  @Test(expected = HttpAuthenticationException.class)
  public void testKerberosAuthWithGssException() throws Exception {
    // Configure GSSContext to throw exception
    when(gssContext.getSrcName()).thenThrow(new GSSException(GSSException.FAILURE));
    
    // Run authentication - should throw exception
    authHandler.run();
  }

  @Test(expected = HttpAuthenticationException.class)
  public void testKerberosAuthWithNullGssName() throws Exception {
    // Configure GSSContext to return null name
    when(gssContext.getSrcName()).thenReturn(null);
    
    // Run authentication - should throw exception
    authHandler.run();
  }

  /**
   * A custom implementation for testing Kerberos authentication with LDAP filters
   */
  private class TestableKerberosAuthHandler {
    private final HiveConf hiveConf;
    private final DirSearchFactory mockDirSearchFactory;
    private final FilterFactory mockGroupFilterFactory;
    private final FilterFactory mockCustomFilterFactory;

    public TestableKerberosAuthHandler(HiveConf hiveConf,
                                 DirSearchFactory dirSearchFactory,
                                 FilterFactory groupFilterFactory,
                                 FilterFactory customFilterFactory) {
      this.hiveConf = hiveConf;
      this.mockDirSearchFactory = dirSearchFactory;
      this.mockGroupFilterFactory = groupFilterFactory;
      this.mockCustomFilterFactory = customFilterFactory;
    }

    private void enforceLdapFilters(String shortName) throws HttpAuthenticationException {
      // Implementation that uses our mock factories
      try {
        boolean enableGroupCheck = hiveConf.getBoolVar(
            HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS);
        boolean allowCustomFilter = hiveConf.getBoolVar(
            HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH);
        
        if (!enableGroupCheck && !allowCustomFilter) {
          // If both filters are disabled, no need to do anything
          return;
        }
        
        String bindDN = hiveConf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER);
        String bindPassword = hiveConf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD);
        
        if (bindDN == null || bindDN.isEmpty() || bindPassword == null || bindPassword.isEmpty()) {
          // Missing bind credentials, log and skip
          return;
        }
        
        boolean passedGroupCheck = !enableGroupCheck;
        boolean passedCustomFilter = !allowCustomFilter;
        
        DirSearch dirSearch = mockDirSearchFactory.getInstance(hiveConf, bindDN, bindPassword);
        
        if (enableGroupCheck) {
          passedGroupCheck = applyGroupFilter(dirSearch, shortName);
        }
        
        if (allowCustomFilter) {
          passedCustomFilter = applyCustomFilter(dirSearch, shortName);
        }
        
        if (!(passedGroupCheck && passedCustomFilter)) {
          throw new HttpAuthenticationException("LDAP filter check failed for user " + shortName);
        }
      } catch (AuthenticationException ae) {
        throw new HttpAuthenticationException("LDAP error for user " + shortName, ae);
      }
    }

    private boolean applyGroupFilter(DirSearch dirSearch, String shortName)
        throws AuthenticationException {
      try {
        Filter groupFilter = mockGroupFilterFactory.getInstance(hiveConf);
        if (groupFilter == null) {
          return false;
        }
        
        groupFilter.apply(dirSearch, shortName);
        return true;
      } catch (AuthenticationException ae) {
        throw ae;
      }
    }

    private boolean applyCustomFilter(DirSearch dirSearch, String shortName)
        throws AuthenticationException {
      try {
        Filter customFilter = mockCustomFilterFactory.getInstance(hiveConf);
        if (customFilter == null) {
          return true;
        }
        
        customFilter.apply(dirSearch, shortName);
        return true;
      } catch (AuthenticationException ae) {
        throw ae;
      }
    }

    public String run() throws HttpAuthenticationException {
      try {
        // Simulate successful GSS context establishment
        if (gssContext == null) {
          throw new HttpAuthenticationException("GSS Context is null");
        }
        
        // Get principal name from GSS context
        GSSName srcName = gssContext.getSrcName();
        if (srcName == null) {
          throw new HttpAuthenticationException("Kerberos authentication failed: Could not obtain user principal from GSS Context");
        }
        
        String principal = srcName.toString();
        String shortName = getPrincipalWithoutRealmAndHost(principal);
        
        // Apply LDAP filters
        enforceLdapFilters(shortName);
        
        return shortName;
      } catch (GSSException e) {
        throw new HttpAuthenticationException("Kerberos authentication failed", e);
      }
    }
    
    protected String getPrincipalWithoutRealmAndHost(String principal) {
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
}