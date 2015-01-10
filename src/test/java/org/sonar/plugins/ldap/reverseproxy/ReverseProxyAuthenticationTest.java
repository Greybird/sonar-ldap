/*
 * Sonar LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * dev@sonar.codehaus.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.plugins.ldap.reverseproxy;

import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.SecurityRealm;
import org.sonar.plugins.ldap.LdapAutodiscovery;
import org.sonar.plugins.ldap.LdapRealm;
import org.sonar.plugins.ldap.LdapSettingsManager;
import org.sonar.plugins.ldap.server.LdapServer;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.fail;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.sonar.plugins.ldap.LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled;

/**
 * Tests the realm.
 */
public class ReverseProxyAuthenticationTest {

  /**
   * A reference to the original ldif file
   */
  public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";

  @ClassRule
  public static LdapServer exampleServer = new LdapServer(USERS_EXAMPLE_ORG_LDIF);

  /**
   * Tests the typical authentication process.
   */
  @Test
  public void testRealm() {
    final Settings settings = generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final SecurityRealm realm = new LdapRealm(settingsManager);
    realm.getName();
    try {
      realm.init();
      fail("Since there is no connection, the init method has to throw an exception.");
    } catch (IllegalStateException e) {
      assertThat(e.getMessage()).contains("Unable to open LDAP connection");
    }

    final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn("godin");
    when(httpServletRequest.getServerName()).thenReturn("not.localhost.com");

    final Authenticator.Context authenticatorContext = new Authenticator.Context(
      null, null, httpServletRequest);
    assertThat(!realm.doGetAuthenticator().doAuthenticate(authenticatorContext));
  }

  /**
   * Tests when the header is missing.
   */
  @Test
  public void testRealmMissingHeader() {
    final Settings settings = generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final SecurityRealm realm = new LdapRealm(settingsManager);
    realm.getName();
    try {
      realm.init();
      fail("Since there is no connection, the init method has to throw an exception.");
    } catch (IllegalStateException e) {
      assertThat(e.getMessage()).contains("Unable to open LDAP connection");
    }

    final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(null);
    when(httpServletRequest.getServerName())
      .thenReturn("not.localhost.com");

    final Authenticator.Context authenticatorContext = new Authenticator.Context(
      null, null, httpServletRequest);
    realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
    assertThat(realm.doGetAuthenticator().doAuthenticate(authenticatorContext));
  }

  /**
   * Tests when the header has empty header value.
   */
  @Test
  public void testRealmMissingHeaderValue() {
    final Settings settings = generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final SecurityRealm realm = new LdapRealm(settingsManager);
    realm.getName();
    try {
      realm.init();
      fail("Since there is no connection, the init method has to throw an exception.");
    } catch (IllegalStateException e) {
      assertThat(e.getMessage()).contains("Unable to open LDAP connection");
    }

    final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn("");
    when(httpServletRequest.getServerName())
      .thenReturn("not.localhost.com");

    final Authenticator.Context authenticatorContext = new Authenticator.Context(
      null, null, httpServletRequest);
    realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
    assertThat(!realm.doGetAuthenticator().doAuthenticate(authenticatorContext));
  }

  /**
   * Tests the typical authentication process when the server request is
   * against localhost.
   */
  @Test
  public void testRealmOnLocalhost() {
    final Settings settings = generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final SecurityRealm realm = new LdapRealm(settingsManager);
    realm.getName();
    try {
      realm.init();
      fail("Since there is no connection, the init method has to throw an exception.");
    } catch (IllegalStateException e) {
      assertThat(e.getMessage()).contains("Unable to open LDAP connection");
    }

    final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn("godin");
    when(httpServletRequest.getServerName()).thenReturn("localhost");

    final Authenticator.Context authenticatorContext = new Authenticator.Context(
      null, null, httpServletRequest);
    assertThat(realm.doGetAuthenticator().doAuthenticate(authenticatorContext));
  }
}
