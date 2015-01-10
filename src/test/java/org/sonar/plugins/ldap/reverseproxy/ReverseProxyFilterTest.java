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
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.LdapAutodiscovery;
import org.sonar.plugins.ldap.LdapSettingsFactory;
import org.sonar.plugins.ldap.LdapSettingsManager;
import org.sonar.plugins.ldap.server.LdapServer;
import org.junit.Test;
import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.ldap.ReverseProxyFilter;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.net.URL;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link ReverseProxyFilter}.
 */
public class ReverseProxyFilterTest {

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


  /**
   * Tests the typical filtering events.
   */
  @Test
  public void testFilter() throws Exception {
    final ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/sonar");
    final FilterConfig filterConfig = mock(FilterConfig.class);
    when(filterConfig.getServletContext()).thenReturn(servletContext);

    final Settings settings = LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final ServletFilter filter = new ReverseProxyFilter(settingsManager);
    filter.init(filterConfig);
    filter.doGetPattern();

    final HttpServletRequest request = mock(HttpServletRequest.class);
    URL url = new URL("http://localhost/sonar/sessions/new");
    when(request.getRequestURL()).thenReturn(new StringBuffer(url.toString()));
    when(request.getServerName()).thenReturn(url.getHost());

    final HttpServletResponse response = mock(HttpServletResponse.class);

    final FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(
      "http://localhost/sonar/ldap/validate");

    filter.destroy();
  }

  /**
   * Tests the typical filtering events with X_FORWARDED_PROTO
   */
  @Test
  public void testFilterWithProtocol() throws Exception {
    final ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/sonar");
    final FilterConfig filterConfig = mock(FilterConfig.class);
    when(filterConfig.getServletContext()).thenReturn(servletContext);

    final Settings settings = LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final ServletFilter filter = new ReverseProxyFilter(settingsManager);
    filter.init(filterConfig);
    filter.doGetPattern();

    final HttpServletRequest request = mock(HttpServletRequest.class);

    URL url = new URL("https://localhost:8322/sonar/sessions/new");
    when(request.getRequestURL()).thenReturn(new StringBuffer(url.toString()));
    when(request.getServerName()).thenReturn(url.getHost());
    when(request.getHeader("X-Forwarded-User")).thenReturn("a_user_name");
    when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");

    final HttpServletResponse response = mock(HttpServletResponse.class);

    final FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(
      "https://localhost:8322/sonar/ldap/validate");

    filter.destroy();
  }

  @Test
  public void testFilterDoesNotRedirectIfNoHeaderSet() throws Exception {
    final ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/sonar");
    final FilterConfig filterConfig = mock(FilterConfig.class);
    when(filterConfig.getServletContext()).thenReturn(servletContext);

    final Settings settings = LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final ServletFilter filter = new ReverseProxyFilter(settingsManager);
    filter.init(filterConfig);
    filter.doGetPattern();

    final HttpServletRequest request = mock(HttpServletRequest.class);
    URL url = new URL("https://localhost/sonar/sessions/new");
    when(request.getRequestURL()).thenReturn(new StringBuffer(url.toString()));
    when(request.getServerName()).thenReturn(url.getHost());
    when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");

    final HttpServletResponse response = mock(HttpServletResponse.class);

    final FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(
      "https://localhost/sonar/ldap/validate");

    filter.destroy();
  }

  @Test
  public void testFilterDoesNotRedirectIfHostNameIsNotCorrect() throws Exception {
    final ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/sonar");
    final FilterConfig filterConfig = mock(FilterConfig.class);
    when(filterConfig.getServletContext()).thenReturn(servletContext);

    final Settings settings = LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final ServletFilter filter = new ReverseProxyFilter(settingsManager);
    filter.init(filterConfig);
    filter.doGetPattern();

    final HttpServletRequest request = mock(HttpServletRequest.class);
    URL url = new URL("https://i.tra.com:8322/sonar/sessions/new");
    when(request.getRequestURL()).thenReturn(new StringBuffer(url.toString()));
    when(request.getServerName()).thenReturn(url.getHost());
    when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");

    final HttpServletResponse response = mock(HttpServletResponse.class);

    final FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response, never()).sendRedirect(
      "https://i.tra.com:8322/sonar/ldap/validate");

    filter.destroy();
  }

  /**
   * Tests the typical filtering events with X_FORWARDED_PROTO and Sonar at
   * root.
   */
  @Test
  public void testFilterWithProtocolAtRoot() throws Exception {
    final ServletContext servletContext = mock(ServletContext.class);
    when(servletContext.getContextPath()).thenReturn("/");
    final FilterConfig filterConfig = mock(FilterConfig.class);
    when(filterConfig.getServletContext()).thenReturn(servletContext);

    final Settings settings = LdapSettingsFactory.generateAuthenticationSettingsWithReverseProxyEnabled(exampleServer, null);
    final LdapSettingsManager settingsManager = new LdapSettingsManager(settings, new LdapAutodiscovery());
    final ServletFilter filter = new ReverseProxyFilter(settingsManager);
    filter.init(filterConfig);
    filter.doGetPattern();

    final HttpServletRequest request = mock(HttpServletRequest.class);
    URL url = new URL("https://localhost/sessions/new");
    when(request.getRequestURL()).thenReturn(new StringBuffer(url.toString()));
    when(request.getServerName()).thenReturn(url.getHost());
    when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");
    when(request.getHeader("X-Forwarded-User")).thenReturn("a_user_name");

    final HttpServletResponse response = mock(HttpServletResponse.class);

    final FilterChain chain = mock(FilterChain.class);
    filter.doFilter(request, response, chain);

    verify(response).sendRedirect(
      "https://localhost/ldap/validate");

    filter.destroy();
  }
}
