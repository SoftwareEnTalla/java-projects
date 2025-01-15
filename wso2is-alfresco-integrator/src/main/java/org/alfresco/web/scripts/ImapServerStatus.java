//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.Response;

public class ImapServerStatus extends SingletonValueProcessorExtension<Boolean> {
    private static Log logger = LogFactory.getLog(ImapServerStatus.class);

    public ImapServerStatus() {
    }

    public boolean getEnabled() {
        return (Boolean)this.getSingletonValue();
    }

    protected Boolean retrieveValue(String userId, String storeId) throws ConnectorServiceException {
        boolean enabled = false;
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", userId, ServletUtil.getSession());
        Response response = conn.call("/imap/servstatus");
        if (response.getStatus().getCode() == 200) {
            enabled = response.getText().equals("enabled");
            logger.info("Successfully retrieved IMAP server status from Alfresco: " + response.getText());
            return enabled;
        } else {
            throw new AlfrescoRuntimeException("Unable to retrieve IMAP server status from Alfresco: " + response.getStatus().getCode());
        }
    }

    protected String getValueName() {
        return "IMAP server status";
    }
}
