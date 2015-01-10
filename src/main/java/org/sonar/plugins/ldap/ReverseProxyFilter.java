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

import org.sonar.api.web.ServletFilter;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * This filter redirects the current request to
 * <code>/reverseproxyauth/validate</code>.
 */
public class ReverseProxyFilter extends ServletFilter {
  private static final String NEW_SESSION_PATH = "/sessions/new";

  private final ReverseProxySettings reverseProxySettings;

  public ReverseProxyFilter(LdapSettingsManager settingsManager) {
    reverseProxySettings = settingsManager.getReverseProxySettings();
  }

  /**
   * Does nothing. {@inheritDoc}
   */
  @Override
  public void destroy() {
    // does nothing.
  }

  /**
   * Perform the redirection and handle the <code>X_FORWARDED_PROTO</code>
   * header as needed. Warnings are suppressed as Sonar treats multiple
   * exceptions as technical debt. {@inheritDoc}
   */
  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
    final HttpServletRequest req = (HttpServletRequest) request;

    if (reverseProxySettings.getReverseProxyUserName(req) != null) {
      final StringBuilder url = new StringBuilder(req.getRequestURL().toString());
      url.replace(url.length() - NEW_SESSION_PATH.length(), url.length(), "/ldap/validate");

      final String forwardedProtocol = req.getHeader("X_FORWARDED_PROTO");
      if (forwardedProtocol != null) {
        url.replace(0, url.indexOf(":"), forwardedProtocol);
      }
      ((HttpServletResponse) response).sendRedirect(url.toString());
    } else {
      chain.doFilter(request, response);
    }

  }

  /**
   * Match against <code>/sessions/new</code>. {@inheritDoc}
   */
  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create(NEW_SESSION_PATH);
  }

  /**
   * Does nothing. {@inheritDoc}
   */
  @Override
  public void init(final FilterConfig filterConfig) throws ServletException {
    // does nothing.
  }
}
