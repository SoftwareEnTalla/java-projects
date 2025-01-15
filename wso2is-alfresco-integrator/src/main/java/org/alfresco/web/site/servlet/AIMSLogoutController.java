//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.alfresco.web.site.servlet.config.AIMSConfig;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.mvc.LogoutController;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

public class AIMSLogoutController extends AbstractController {
    protected AIMSConfig config;
    protected LogoutController logoutController;
    private ApplicationContext applicationContext;
    private AIMSLogoutHandler aimsLogoutHandler;

    public AIMSLogoutController() {
    }

    public void setConfig(AIMSConfig config) {
        this.config = config;
    }

    public void setLogoutController(LogoutController logoutController) {
        this.logoutController = logoutController;
    }

    protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if (this.config.isEnabled()) {
            if (request.getParameter("success") != null) {
                this.logoutController.handleRequestInternal(request, response);
                this.doRedirect(response, request.getContextPath());
            } else {
                this.applicationContext = WebApplicationContextUtils.getRequiredWebApplicationContext(super.getServletContext());
                this.aimsLogoutHandler = (AIMSLogoutHandler)this.applicationContext.getBean(AIMSLogoutHandler.class);
                HttpSession session = request.getSession(false);
                if (session != null) {
                    String userId = (String)session.getAttribute("_alf_USER_ID");
                    if (userId != null) {
                        SecurityContext account = (SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT");
                        if (account != null) {
                            try {
                                this.aimsLogoutHandler.handle(request, response, account.getAuthentication());
                            } catch (ServletException | IOException var7) {
                                throw new RuntimeException(var7);
                            }
                        }
                    }
                }
            }
        }

        return null;
    }

    protected void doRedirect(HttpServletResponse response, String location) {
        response.setStatus(301);
        response.setHeader("Location", location);
        response.setHeader("Cache-Control", "max-age=0");
    }
}
