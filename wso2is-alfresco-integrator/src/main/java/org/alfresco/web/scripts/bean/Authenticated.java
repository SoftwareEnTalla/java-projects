//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts.bean;

import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.connector.User;
import org.springframework.extensions.webscripts.servlet.WebScriptServletRequest;

public class Authenticated extends DeclarativeWebScript {
    public Authenticated() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status) {
        if (req instanceof WebScriptServletRequest webScriptServletRequest) {
            HttpSession session = webScriptServletRequest.getHttpServletRequest().getSession(false);
            boolean isAllowedToViewPage = false;
            if (session != null) {
                String userID = (String)session.getAttribute("_alf_USER_ID");
                if (userID != null && !"guest".equals(userID)) {
                    User user = (User)session.getAttribute("_alf_USER_OBJECT");
                    String auth = webScriptServletRequest.getHttpServletRequest().getParameter("a");
                    if (user != null) {
                        isAllowedToViewPage = auth != null && auth.equals("admin") ? user.isAdmin() : true;
                    }
                }
            }

            if (!isAllowedToViewPage) {
                status.setCode(401);
                status.setMessage("There is no user ID in session or user is not permitted to view the page");
                status.setRedirect(true);
            }
        }

        return null;
    }
}
