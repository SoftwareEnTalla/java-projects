package cu.entalla.controller;


import cu.entalla.config.Wso2Config;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.mvc.LogoutController;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import java.io.IOException;

public class Wso2LogoutController extends AbstractController {
    protected Wso2Config config;
    protected LogoutController logoutController;
    private ApplicationContext applicationContext;
    private Wso2LogoutHandler wso2LogoutHandler;

    public Wso2LogoutController() {
    }

    public void setConfig(Wso2Config config) {
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
                this.wso2LogoutHandler = (Wso2LogoutHandler)this.applicationContext.getBean(Wso2LogoutHandler.class);
                HttpSession session = request.getSession(false);
                if (session != null) {
                    String userId = (String)session.getAttribute("_alf_USER_ID");
                    if (userId != null) {
                        SecurityContext account = (SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT");
                        if (account != null) {
                            try {
                                this.wso2LogoutHandler.handle(request, response, account.getAuthentication());
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