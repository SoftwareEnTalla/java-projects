//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmis;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.alfresco.cmis.client.impl.AlfrescoObjectFactoryImpl;
import org.apache.chemistry.opencmis.commons.enums.BindingType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.cmis.CMISConnection;
import org.springframework.extensions.cmis.CMISConnectionManagerImpl;
import org.springframework.extensions.cmis.CMISScriptParameterFactory;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.AuthenticatingConnector;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Credentials;

public class SlingshotCMISScriptParameterFactory extends CMISScriptParameterFactory {
    private static final Log logger = LogFactory.getLog(SlingshotCMISScriptParameterFactory.class);
    private static final String CMIS_PATH = "/cmisatom";
    private static final String ALFRESCO_SERVICE_BASE_PATH = "/s";
    private ConnectorService connectorService;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public SlingshotCMISScriptParameterFactory() {
    }

    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    public CMISConnection getConnection(CMISConnectionManagerImpl connectionManager) {
        this.lock.writeLock().lock();
        CMISConnection connection=null;
        RequestContext rc=null;
        try {
            connection = super.getConnection(connectionManager);
            if (connection != null) {
                CMISConnection var16 = connection;
                return var16;
            }

            if (ThreadLocalRequestContext.getRequestContext() != null) {
                rc = ThreadLocalRequestContext.getRequestContext();
                Credentials creds = rc.getCredentialVault().retrieve("alfresco");

                Connector connector;
                String url;
                try {
                    connector = this.connectorService.getConnector("alfresco");
                    connector.setCredentials(creds);
                } catch (Exception var14) {
                    logger.info("Unable to get endpoint connector: " + var14, var14);
                    return null;
                }

                String alfrescoEndpointUrl = connector.getEndpoint();
                if (alfrescoEndpointUrl.endsWith("/s")) {
                    alfrescoEndpointUrl = alfrescoEndpointUrl.substring(0, alfrescoEndpointUrl.length() - "/s".length());
                }

                url = alfrescoEndpointUrl + "/cmisatom";
                Map<String, String> parameters = new HashMap();
                parameters.put("name", "default-" + rc.getUserId());
                parameters.put("org.apache.chemistry.opencmis.binding.spi.type", BindingType.ATOMPUB.value());
                parameters.put("org.apache.chemistry.opencmis.binding.atompub.url", url);
                parameters.put("org.apache.chemistry.opencmis.objectfactory.classname", AlfrescoObjectFactoryImpl.class.getName());
                String ticket = this.getTicket(connector);
                CMISConnection var10;
                if (ticket != null) {
                    parameters.put("org.apache.chemistry.opencmis.user", "");
                    parameters.put("org.apache.chemistry.opencmis.password", ticket);
                } else {
                    if (creds == null) {
                        var10 = null;
                        return var10;
                    }

                    parameters.put("org.apache.chemistry.opencmis.user", (String)creds.getProperty("cleartextUsername"));
                    parameters.put("org.apache.chemistry.opencmis.password", (String)creds.getProperty("cleartextPassword"));
                }

                var10 = this.createDefaultConnection(connectionManager, createServerDefinition(parameters));
                return var10;
            }
            rc = null;
        } finally {
            this.lock.writeLock().unlock();
        }

        return connection;
    }

    private String getTicket(Connector connector) {
        String ticket = connector.getConnectorSession().getParameter("alfTicket");
        if (ticket != null) {
            return ticket;
        } else {
            return connector instanceof AuthenticatingConnector && ((AuthenticatingConnector)connector).handshake() ? connector.getConnectorSession().getParameter("alfTicket") : null;
        }
    }
}
