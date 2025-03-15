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
package org.apache.hive.service.auth.ldap;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.security.SaslRpcServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.AuthorizeCallback;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

/**
 * Tests for the LdapGroupCallbackHandler used for Kerberos authentication with LDAP group filtering.
 * Uses Mockito for mocking LDAP components.
 */
@RunWith(MockitoJUnitRunner.class)
public class TestLdapGroupCallbackHandler {

  private static final String TEST_USER = "user";
  private static final String TEST_PRINCIPAL = TEST_USER + "@TEST.REALM";

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
  private LdapGroupCallbackHandler callbackHandler;

  @Mock
  private javax.security.auth.callback.CallbackHandler delegateHandler;

  @Before
  public void setup() throws Exception {
    conf = new HiveConf();
    
    // Set up bind user and password
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER, "bindUser");
    conf.setVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_PASSWORD, "bindPassword");
    
    // Setup mock factories
    mockDirSearchFactory();
    mockFilterFactories();
    
    // Create the callback handler
    callbackHandler = new MockedLdapGroupCallbackHandler(conf, dirSearchFactory, 
        groupFilterFactory, customFilterFactory, delegateHandler);
  }
  
  /**
   * Custom implementation of LdapGroupCallbackHandler for testing.
   */
  private static class MockedLdapGroupCallbackHandler extends LdapGroupCallbackHandler {
    public MockedLdapGroupCallbackHandler(HiveConf conf, 
                                       DirSearchFactory dirSearchFactory,
                                       FilterFactory groupFilterFactory,
                                       FilterFactory customFilterFactory,
                                       javax.security.auth.callback.CallbackHandler delegateHandler) {
      super(conf);
      
      // Use reflection to override the delegate handler
      try {
        java.lang.reflect.Field delegateHandlerField = LdapGroupCallbackHandler.class.getDeclaredField("delegateHandler");
        delegateHandlerField.setAccessible(true);
        delegateHandlerField.set(this, delegateHandler);
      } catch (Exception e) {
        throw new RuntimeException("Failed to set delegate handler", e);
      }
    }
  }

  private void mockDirSearchFactory() throws Exception {
    when(dirSearchFactory.getInstance(any(HiveConf.class), anyString(), anyString()))
        .thenReturn(dirSearch);
  }

  private void mockFilterFactories() throws Exception {
    when(groupFilterFactory.getInstance(any(HiveConf.class))).thenReturn(groupFilter);
    when(customFilterFactory.getInstance(any(HiveConf.class))).thenReturn(customFilter);
    
    // Configure filters to succeed by default
    doNothing().when(groupFilter).apply(any(DirSearch.class), anyString());
    doNothing().when(customFilter).apply(any(DirSearch.class), anyString());
  }

  @Test
  public void testAuthorizeWithNoLdapFilter() throws Exception {
    // Disable both LDAP filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, false);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was authorized
    assertTrue(ac.isAuthorized());
    
    // Verify no LDAP operations occurred
    verifyNoInteractions(dirSearch, groupFilter, customFilter);
  }

  @Test
  public void testAuthorizeWithGroupFilterSuccess() throws Exception {
    // Enable only group filter
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, false);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was authorized
    assertTrue(ac.isAuthorized());
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(conf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verifyNoInteractions(customFilter);
  }

  @Test
  public void testAuthorizeWithCustomFilterSuccess() throws Exception {
    // Enable only custom filter
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, false);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was authorized
    assertTrue(ac.isAuthorized());
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
    verify(customFilterFactory).getInstance(eq(conf));
    verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
    verifyNoInteractions(groupFilter);
  }

  @Test
  public void testAuthorizeWithBothFiltersSuccess() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was authorized
    assertTrue(ac.isAuthorized());
    
    // Verify LDAP operations
    verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(conf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verify(customFilterFactory).getInstance(eq(conf));
    verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
  }

  @Test
  public void testAuthorizeWithGroupFilterFailure() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Configure group filter to fail
    doThrow(new AuthenticationException("User not in required group"))
        .when(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was NOT authorized
    assertFalse(ac.isAuthorized());
    
    // Verify LDAP operations - only group filter should have been called
    verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(conf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verifyNoInteractions(customFilter);
  }

  @Test
  public void testAuthorizeWithCustomFilterFailure() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Configure group filter to pass but custom filter to fail
    doNothing().when(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    doThrow(new AuthenticationException("Custom filter failed"))
        .when(customFilter).apply(eq(dirSearch), eq(TEST_USER));
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was NOT authorized
    assertFalse(ac.isAuthorized());
    
    // Verify LDAP operations - both filters should have been called
    verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
    verify(groupFilterFactory).getInstance(eq(conf));
    verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
    verify(customFilterFactory).getInstance(eq(conf));
    verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
  }

  @Test
  public void testDelegationWithDifferentAuthIds() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Create an AuthorizeCallback with different authentication and authorization IDs
    String authenticationId = TEST_PRINCIPAL;
    String authorizationId = "anotheruser@TEST.REALM";
    AuthorizeCallback ac = new AuthorizeCallback(authenticationId, authorizationId);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify delegation occurred by verifying delegateHandler was called with the AuthorizeCallback
    verify(delegateHandler).handle(argThat(callbackArray -> 
        callbackArray.length == 1 && callbackArray[0] == ac));
    
    // Verify no LDAP operations occurred since it should be handled by the delegate
    verifyNoInteractions(dirSearch, groupFilter, customFilter);
  }

  @Test
  public void testAuthorizeWithMissingBindCredentials() throws Exception {
    // Enable both filters but remove bind credentials
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    conf.unset(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BIND_USER.varname);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    // Handle the callback
    callbackHandler.handle(callbacks);
    
    // Verify the user was NOT authorized (credentials required but missing)
    assertFalse(ac.isAuthorized());
    
    // Verify no LDAP operations occurred
    verifyNoInteractions(dirSearch, groupFilter, customFilter);
  }

  @Test
  public void testHandleUnsupportedCallback() throws Exception {
    // Create a non-AuthorizeCallback
    Callback unsupportedCallback = mock(Callback.class);
    Callback[] callbacks = {unsupportedCallback};
    
    try {
      // Handle the callback - should delegate to SaslGssCallbackHandler
      callbackHandler.handle(callbacks);
      
      // If we reach here, the test fails
      fail("Expected UnsupportedCallbackException");
    } catch (UnsupportedCallbackException e) {
      // Expected
      assertEquals(unsupportedCallback, e.getCallback());
    }
  }

  @Test
  public void testHandleMixedCallbacks() throws Exception {
    // Enable both filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Create a mix of callbacks - one AuthorizeCallback and one unsupported
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback unsupportedCallback = mock(Callback.class);
    Callback[] callbacks = {ac, unsupportedCallback};
    
    try {
      // Handle the callbacks - should process AuthorizeCallback and delegate the other
      callbackHandler.handle(callbacks);
      
      // If we reach here, the test fails
      fail("Expected UnsupportedCallbackException");
    } catch (UnsupportedCallbackException e) {
      // Expected
      assertEquals(unsupportedCallback, e.getCallback());
      
      // Verify the AuthorizeCallback was processed
      assertTrue(ac.isAuthorized());
      
      // Verify LDAP operations
      verify(dirSearchFactory).getInstance(eq(conf), eq("bindUser"), eq("bindPassword"));
      verify(groupFilterFactory).getInstance(eq(conf));
      verify(groupFilter).apply(eq(dirSearch), eq(TEST_USER));
      verify(customFilterFactory).getInstance(eq(conf));
      verify(customFilter).apply(eq(dirSearch), eq(TEST_USER));
    }
  }
  
  @Test
  public void testAuthorizeWithProxyUser() throws Exception {
    // Enable both LDAP filters
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ENABLE_GROUP_CHECK_AFTER_KERBEROS, true);
    conf.setBoolVar(HiveConf.ConfVars.HIVE_SERVER2_LDAP_ALLOW_CUSTOM_LDAP_FILTERS_WITH_KERBEROS_AUTH, true);
    
    // Create an AuthorizeCallback for the test user
    AuthorizeCallback ac = new AuthorizeCallback(TEST_PRINCIPAL, TEST_PRINCIPAL);
    Callback[] callbacks = {ac};
    
    try {
      // Set up a proxy user
      java.lang.reflect.Method setProxyMethod = 
          org.apache.hive.service.cli.session.SessionManager.class.getMethod("setProxyUserName", String.class);
      setProxyMethod.invoke(null, "proxyUser");
      
      // Handle the callback
      callbackHandler.handle(callbacks);
      
      // Verify the user was authorized (should be authorized even with filters enabled)
      assertTrue(ac.isAuthorized());
      
      // Verify no LDAP operations occurred since it should skip filters for proxy users
      verifyNoInteractions(dirSearch, groupFilter, customFilter);
    } finally {
      // Clean up
      java.lang.reflect.Method clearProxyMethod = 
          org.apache.hive.service.cli.session.SessionManager.class.getMethod("clearProxyUserName");
      clearProxyMethod.invoke(null);
    }
  }

}