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

import javax.servlet.http.HttpServletRequest;

import org.sonar.api.config.Settings;
import org.sonar.api.utils.MessageException;

public class ReverseProxySettings {

  private static final String LDAP_REVERSE_PROXY_ENABLED_SETTING = "ldap.reverseproxy.enabled";
  private static final String LDAP_REVERSE_PROXY_HEADER_NAME_SETTING = "ldap.reverseproxy.header.name";
  private final boolean isEnabled;
  private final String usernameHeader;

  public ReverseProxySettings(Settings settings) {
    if (settings.hasKey(LDAP_REVERSE_PROXY_ENABLED_SETTING)) {
      isEnabled = settings.getBoolean(LDAP_REVERSE_PROXY_ENABLED_SETTING);
    } else {
      isEnabled = false;
    }
    if (isEnabled) {
      if (!settings.hasKey(LDAP_REVERSE_PROXY_HEADER_NAME_SETTING)) {
        throw MessageException.of("Reverse Proxy is enabled but no header name is set");
      }
      usernameHeader = settings.getString(LDAP_REVERSE_PROXY_HEADER_NAME_SETTING);
    } else {
      usernameHeader = null;
    }
  }

  public boolean getIsEnabled() {
    return isEnabled;
  }

  public String getUsernameHeader() {
    return usernameHeader;
  }

  /**
   * @return user to use for reverse proxy authentication, or null if situation is not ok to try this.
   */
  public String getReverseProxyUserName(HttpServletRequest request) {
    if (getIsEnabled()) {
      final String headerValue = request.getHeader(getUsernameHeader());
      if (headerValue != null)
      {
        String trimmerHeaderValue = headerValue.trim();
        if (!trimmerHeaderValue.isEmpty())
        {
          return trimmerHeaderValue;
        }
      }
    }
    return null;
  }
}
