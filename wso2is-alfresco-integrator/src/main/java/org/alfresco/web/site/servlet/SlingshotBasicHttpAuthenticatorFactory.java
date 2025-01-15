//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.http.HttpSession;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.webscripts.Authenticator;
import org.springframework.extensions.webscripts.BasicHttpAuthenticatorFactory;
import org.springframework.extensions.webscripts.Description;
import org.springframework.extensions.webscripts.connector.User;
import org.springframework.extensions.webscripts.servlet.WebScriptServletRequest;
import org.springframework.extensions.webscripts.servlet.WebScriptServletResponse;

public class SlingshotBasicHttpAuthenticatorFactory extends BasicHttpAuthenticatorFactory {
    public SlingshotBasicHttpAuthenticatorFactory() {
    }

    public Authenticator create(WebScriptServletRequest req, WebScriptServletResponse res) {
        Authenticator auth = null;
        final HttpSession session;
        switch (req.getServiceMatch().getWebScript().getDescription().getRequiredAuthentication()) {
            case admin:
                session = req.getHttpServletRequest().getSession(false);
                if (session != null) {
                    User user = (User)session.getAttribute("_alf_USER_OBJECT");
                    if (user != null && user.isAdmin()) {
                        auth = new Authenticator() {
                            public boolean emptyCredentials() {
                                return false;
                            }

                            public boolean authenticate(Description.RequiredAuthentication required, boolean isGuest) {
                                return true;
                            }
                        };
                    } else {
                        auth = super.create(req, res);
                    }
                } else {
                    auth = super.create(req, res);
                }
                break;
            case user:
                session = req.getHttpServletRequest().getSession(false);
                if (session != null) {
                    auth = new Authenticator() {
                        public boolean emptyCredentials() {
                            return false;
                        }

                        public boolean authenticate(Description.RequiredAuthentication required, boolean isGuest) {
                            User user = (User)session.getAttribute("_alf_USER_OBJECT");
                            return user != null && !AuthenticationUtil.isGuest(user.getId());
                        }
                    };
                }
                break;
            case guest:
                session = req.getHttpServletRequest().getSession(false);
                if (session != null) {
                    auth = new Authenticator() {
                        public boolean emptyCredentials() {
                            return false;
                        }

                        public boolean authenticate(Description.RequiredAuthentication required, boolean isGuest) {
                            User user = (User)session.getAttribute("_alf_USER_OBJECT");
                            return user != null && AuthenticationUtil.isGuest(user.getId());
                        }
                    };
                }
        }

        return auth;
    }
}
