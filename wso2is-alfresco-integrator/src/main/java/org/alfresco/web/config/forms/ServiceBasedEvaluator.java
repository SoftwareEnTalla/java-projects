//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.springframework.extensions.config.evaluator.Evaluator;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Response;

public abstract class ServiceBasedEvaluator implements Evaluator {
    protected static final String ENDPOINT_ID = "alfresco";

    public ServiceBasedEvaluator() {
    }

    protected abstract Log getLogger();

    protected String callService(String serviceUrl) throws ConnectorServiceException {
        StringBuilder builder = (new StringBuilder()).append("forms.cache.").append(serviceUrl);
        String keyForCachedJson = builder.toString();
        Map<String, Serializable> valuesMap = ThreadLocalRequestContext.getRequestContext().getValuesMap();
        Serializable cachedResult = (Serializable)valuesMap.get(keyForCachedJson);
        if (cachedResult != null & cachedResult instanceof String) {
            if (this.getLogger().isDebugEnabled()) {
                this.getLogger().debug("Retrieved cached response for " + serviceUrl);
            }

            return (String)cachedResult;
        } else {
            ConnectorService connService = FrameworkUtil.getConnectorService();
            RequestContext requestContext = ThreadLocalRequestContext.getRequestContext();
            String currentUserId = requestContext.getUserId();
            HttpSession currentSession = ServletUtil.getSession(true);
            Connector connector = connService.getConnector("alfresco", currentUserId, currentSession);
            Response r = connector.call(serviceUrl);
            if (r.getStatus().getCode() == 401) {
                throw new NotAuthenticatedException();
            } else {
                String jsonResponseString = r.getResponse();
                if (this.getLogger().isDebugEnabled()) {
                    this.getLogger().debug("Caching response for " + serviceUrl + ":\n" + jsonResponseString);
                }

                ThreadLocalRequestContext.getRequestContext().setValue(keyForCachedJson, jsonResponseString);
                return jsonResponseString;
            }
        }
    }

    class NotAuthenticatedException extends RuntimeException {
        private static final long serialVersionUID = -4906852539344031273L;

        NotAuthenticatedException() {
        }
    }
}
