//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import org.alfresco.error.AlfrescoRuntimeException;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public class UserPreferences extends BaseProcessorExtension {
    private static final String USER_PREFERENCES = "_alfUserPreferences";

    public UserPreferences() {
    }

    public String getValue() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        String prefs = (String)rc.getValue("_alfUserPreferences");
        if (prefs == null) {
            prefs = "{}";
            if (!AuthenticationUtil.isGuest(rc.getUserId())) {
                try {
                    Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", rc.getUserId(), ServletUtil.getSession());
                    Response response = conn.call("/api/people/" + URLEncoder.encode(rc.getUserId()) + "/preferences");
                    if (response.getStatus().getCode() == 200) {
                        prefs = response.getResponse();
                        rc.setValue("_alfUserPreferences", prefs);
                    }
                } catch (ConnectorServiceException var5) {
                    throw new AlfrescoRuntimeException("Unable to retrieve user preferences: " + var5.getMessage(), var5);
                }
            }
        }

        return prefs;
    }
}
