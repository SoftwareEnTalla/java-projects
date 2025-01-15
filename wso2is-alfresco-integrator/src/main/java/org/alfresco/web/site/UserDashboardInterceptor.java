//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.alfresco.web.site.servlet.MTAuthenticationFilter;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.WebFrameworkServiceRegistry;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.mvc.AbstractWebFrameworkInterceptor;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.URLDecoder;
import org.springframework.extensions.webscripts.connector.User;
import org.springframework.ui.ModelMap;
import org.springframework.web.context.request.WebRequest;

public class UserDashboardInterceptor extends AbstractWebFrameworkInterceptor {
    private static final Pattern PATTERN_DASHBOARD_PATH = Pattern.compile(".*/user/([^/]*)/dashboard");

    public UserDashboardInterceptor() {
    }

    public void preHandle(WebRequest request) throws Exception {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        String pathInfo = rc.getUri();
        Matcher matcher;
        if (pathInfo != null && (matcher = PATTERN_DASHBOARD_PATH.matcher(pathInfo)).matches()) {
            HttpServletRequest req = MTAuthenticationFilter.getCurrentServletRequest();
            if (req != null) {
                try {
                    ServletUtil.setRequest(req);
                    RequestContextUtil.populateRequestContext(rc, req);
                    String userid = rc.getUserId();
                    String usernameFromURL = URLDecoder.decode(matcher.group(1));
                    if (this.isUserIDMatchingUsernameFromURL(userid, usernameFromURL)) {
                        WebFrameworkServiceRegistry serviceRegistry = rc.getServiceRegistry();
                        if (serviceRegistry.getModelObjectService().getPage("user/" + userid + "/dashboard") == null) {
                            Map<String, String> tokens = new HashMap(2);
                            tokens.put("userid", userid);
                            serviceRegistry.getPresetsManager().constructPreset("user-dashboard", tokens);
                        }
                    } else {
                        rc.setUser((User)null);
                        rc.setPage(ThreadLocalRequestContext.getRequestContext().getRootPage());
                    }
                } catch (UserFactoryException var10) {
                }
            }
        }

    }

    private boolean isUserIDMatchingUsernameFromURL(String userid, String usernameFromURL) {
        if (userid != null && usernameFromURL != null) {
            return this.shouldUseCaseSensitiveUsernameCompare() ? userid.equals(usernameFromURL) : userid.equalsIgnoreCase(usernameFromURL);
        } else {
            return false;
        }
    }

    private boolean shouldUseCaseSensitiveUsernameCompare() {
        return false;
    }

    public void postHandle(WebRequest request, ModelMap model) throws Exception {
    }

    public void afterCompletion(WebRequest request, Exception ex) throws Exception {
    }
}
