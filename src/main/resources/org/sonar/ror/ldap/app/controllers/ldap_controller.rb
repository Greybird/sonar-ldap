class LdapController < ApplicationController
  skip_before_filter :check_authentication
  def validate
    header_name = "HTTP_" + Api::Utils.java_facade.getSettings().getString('ldap.reverseproxy.header.name').upcase
    user_name = request.headers[header_name]
    self.current_user = User.authenticate(user_name, nil, servlet_request)
    redirect_back_or_default(home_url)
  end
end
