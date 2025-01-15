//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import org.apache.commons.codec.binary.Base64;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.webscripts.RequestCachingConnector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.RemoteClient;

public class SlingshotAlfrescoConnector extends RequestCachingConnector {
    private static final String CD_USER_HEADER = "userHeader";
    private static final String CD_USER_ID_PATTERN = "userIdPattern";
    public static final String CS_PARAM_USER_HEADER = "userHeader";
    public static final String CS_PARAM_USER_ID_PATTERN = "userIdPattern";

    public SlingshotAlfrescoConnector(RemoteConfigElement.ConnectorDescriptor descriptor, String endpoint) {
        super(descriptor, endpoint);
    }

    private String getUserHeader() {
        String userHeader = this.descriptor.getStringProperty("userHeader");
        if (userHeader != null && userHeader.trim().length() == 0) {
            userHeader = null;
        }

        return userHeader;
    }

    private String getUserIdPattern() {
        String userIdPattern = this.descriptor.getStringProperty("userIdPattern");
        if (userIdPattern != null && userIdPattern.trim().length() == 0) {
            userIdPattern = null;
        }

        return userIdPattern;
    }

    public void setConnectorSession(ConnectorSession connectorSession) {
        super.setConnectorSession(connectorSession);
        connectorSession.setParameter("userHeader", this.getUserHeader());
        connectorSession.setParameter("userIdPattern", this.getUserIdPattern());
    }

    protected void applyRequestHeaders(RemoteClient remoteClient, ConnectorContext context) {
        ConnectorSession connectorSession = this.getConnectorSession();
        HashMap headers;
        if (connectorSession != null) {
            headers = new HashMap(8);
            String[] var5 = connectorSession.getCookieNames();
            int var6 = var5.length;

            for(int var7 = 0; var7 < var6; ++var7) {
                String cookieName = var5[var7];
                headers.put(cookieName, connectorSession.getCookie(cookieName));
            }

            remoteClient.setCookies(headers);
        }

        headers = new HashMap(8);
        if (context != null) {
            headers.putAll(context.getHeaders());
        }

        if (this.getCredentials() != null) {
            String userHeader = this.getUserHeader();
            if (userHeader != null) {
                HttpServletRequest req = ServletUtil.getRequest();
                if (req == null) {
                    req = MTAuthenticationFilter.getCurrentServletRequest();
                }

                String user = null;
                if (req != null) {
                    user = req.getHeader(userHeader);
                    if (user == null) {
                        user = req.getRemoteUser();
                    }
                }

                if (user != null) {
                    if (!Base64.isBase64(user)) {
                        try {
                            user = Base64.encodeBase64String((new String(user.getBytes("ISO-8859-1"), "UTF-8")).getBytes("UTF-8"));
                        } catch (UnsupportedEncodingException var9) {
                        }

                        headers.put("Remote-User-Encode", Boolean.TRUE.toString());
                    }

                    headers.put(userHeader, user);
                }
            }
        }

        if (headers.size() != 0) {
            remoteClient.setRequestProperties(headers);
        }

    }
}
