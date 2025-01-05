package cu.entalla.service;

import cu.entalla.udi.AlfrescoIntegration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ServiceLocator {
    private static AlfrescoIntegration alfrescoIntegration;

    public static void registerAlfrescoIntegration(AlfrescoIntegration integration) {
        alfrescoIntegration = integration;
    }
    public static AlfrescoIntegration getAlfrescoIntegration() {
        if (alfrescoIntegration == null) {
            throw new IllegalStateException("No AlfrescoIntegration implementation registered!");
        }
        return alfrescoIntegration;
    }

}
