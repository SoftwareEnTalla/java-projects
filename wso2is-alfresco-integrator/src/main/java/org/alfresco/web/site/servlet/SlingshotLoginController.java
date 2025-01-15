//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Iterator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.mvc.LoginController;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;

public class SlingshotLoginController extends LoginController {
    public static String SESSION_ATTRIBUTE_KEY_USER_GROUPS = "_alf_USER_GROUPS";

    public SlingshotLoginController() {
    }

    protected void onSuccess(HttpServletRequest request, HttpServletResponse response) throws Exception {
        this.beforeSuccess(request, response);
        super.onSuccess(request, response);
    }

    public void beforeSuccess(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            HttpSession session = request.getSession();
            String username = request.getParameter("username");
            if (username == null) {
                username = (String)session.getAttribute("_alf_USER_ID");
            }

            if (username != null && session.getAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS) == null) {
                Connector conn = FrameworkUtil.getConnector(session, username, "alfresco");
                ConnectorContext c = new ConnectorContext(HttpMethod.GET);
                c.setContentType("application/json");
                Response res = conn.call("/api/people/" + URLEncoder.encode(username) + "?groups=true", c);
                if (200 == res.getStatus().getCode()) {
                    String resStr = res.getResponse();
                    JSONParser jp = new JSONParser();
                    Object userData = jp.parse(resStr.toString());
                    StringBuilder groups = new StringBuilder(512);
                    if (userData instanceof JSONObject) {
                        Object groupsArray = ((JSONObject)userData).get("groups");
                        if (groupsArray instanceof JSONArray) {
                            Iterator var13 = ((JSONArray)groupsArray).iterator();

                            while(var13.hasNext()) {
                                Object groupData = var13.next();
                                if (groupData instanceof JSONObject) {
                                    Object groupName = ((JSONObject)groupData).get("itemName");
                                    if (groupName != null) {
                                        groups.append(groupName.toString()).append(',');
                                    }
                                }
                            }
                        }
                    }

                    if (groups.length() != 0) {
                        groups.delete(groups.length() - 1, groups.length());
                    }

                    session.setAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS, groups.toString());
                } else {
                    session.setAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS, "");
                }
            }

        } catch (ConnectorServiceException var16) {
            throw new Exception("Error creating remote connector to request user group data.");
        }
    }
}
