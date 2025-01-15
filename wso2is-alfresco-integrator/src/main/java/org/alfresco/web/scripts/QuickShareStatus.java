//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.io.Serializable;
import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.Response;

public class QuickShareStatus extends SingletonValueProcessorExtension<Boolean> implements Serializable {
    private static Log logger = LogFactory.getLog(QuickShareStatus.class);

    public QuickShareStatus() {
    }

    public boolean getEnabled() {
        return (Boolean)this.getSingletonValue();
    }

    protected Boolean retrieveValue(String userId, String storeId) throws ConnectorServiceException {
        boolean enabled = false;
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", userId, ServletUtil.getSession());
        Response response = conn.call("/quickshare/enabled");
        if (response.getStatus().getCode() == 200) {
            logger.info("Successfully retrieved quick share information from Alfresco.");

            try {
                JSONObject json = new JSONObject(response.getResponse());
                if (json.has("enabled")) {
                    enabled = json.getBoolean("enabled");
                }
            } catch (JSONException var8) {
                throw new AlfrescoRuntimeException(var8.getMessage(), var8);
            }

            return enabled;
        } else {
            throw new AlfrescoRuntimeException("Unable to retrieve quick share information from Alfresco: " + response.getStatus().getCode());
        }
    }

    protected String getValueName() {
        return "Quick Share enabled";
    }
}
