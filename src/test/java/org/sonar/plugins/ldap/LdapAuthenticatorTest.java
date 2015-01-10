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
package org.sonar.plugins.ldap;

import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.api.security.Authenticator.Context;
import org.sonar.plugins.ldap.server.LdapServer;

import javax.servlet.http.HttpServletRequest;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.sonar.plugins.ldap.LdapSettingsFactory.generateAuthenticationSettings;

public class LdapAuthenticatorTest {
  /**
   * A reference to the original ldif file
   */
  public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";
  /**
   * A reference to an aditional ldif file.
   */
  public static final String USERS_INFOSUPPORT_COM_LDIF = "/users.infosupport.com.ldif";

  @ClassRule
  public static LdapServer exampleServer = new LdapServer(USERS_EXAMPLE_ORG_LDIF);
  @ClassRule
  public static LdapServer infosupportServer = new LdapServer(USERS_INFOSUPPORT_COM_LDIF, "infosupport.com", "dc=infosupport,dc=com");

  @Test
  public void testNoConnection() {
    exampleServer.disableAnonymousAccess();
    try {
      LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(exampleServer, null), new LdapAutodiscovery());
      LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager);
      authenticator.doAuthenticate(new Context("godin", "secret1", mock(HttpServletRequest.class)));
    } finally {
      exampleServer.enableAnonymousAccess();
    }
  }

  @Test
  public void testSimple() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(exampleServer, null), new LdapAutodiscovery());
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager);

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", mock(HttpServletRequest.class)))).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.doAuthenticate(new Context("godin", "", mock(HttpServletRequest.class)))).isFalse();
    assertThat(authenticator.doAuthenticate(new Context("godin", null, mock(HttpServletRequest.class)))).isFalse();
  }

  @Test
  public void testSimpleMultiLdap() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(exampleServer, infosupportServer), new LdapAutodiscovery());
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager);

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", mock(HttpServletRequest.class)))).isFalse();
    // SONARPLUGINS-2493
    assertThat(authenticator.doAuthenticate(new Context("godin", "", mock(HttpServletRequest.class)))).isFalse();
    assertThat(authenticator.doAuthenticate(new Context("godin", null, mock(HttpServletRequest.class)))).isFalse();

    // SONARPLUGINS-2793
    assertThat(authenticator.doAuthenticate(new Context("robby", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("robby", "wrong", mock(HttpServletRequest.class)))).isFalse();
  }

  @Test
  public void testSasl() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(exampleServer, null), new LdapAutodiscovery());
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager);

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", mock(HttpServletRequest.class)))).isFalse();
  }

  @Test
  public void testSaslMultipleLdap() {
    LdapSettingsManager settingsManager = new LdapSettingsManager(generateAuthenticationSettings(exampleServer, infosupportServer), new LdapAutodiscovery());
    LdapAuthenticator authenticator = new LdapAuthenticator(settingsManager);

    assertThat(authenticator.doAuthenticate(new Context("godin", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("godin", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("tester", "secret2", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("tester", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("notfound", "wrong", mock(HttpServletRequest.class)))).isFalse();

    assertThat(authenticator.doAuthenticate(new Context("robby", "secret1", mock(HttpServletRequest.class)))).isTrue();
    assertThat(authenticator.doAuthenticate(new Context("robby", "wrong", mock(HttpServletRequest.class)))).isFalse();
  }

}
