package cu.entalla.udi;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public interface AlfrescoIntegration {
    String getAlfTicket(String sessionId, String username, String accessToken);

    ApplicationContext getApplicationContext();

    AlfrescoIntegration setApplicationContext(ApplicationContext context);
    String getAlfTicket(String accessToken);
    AlfrescoIntegration configureSession(HttpSession session, String username, String alfTicket);

    AlfrescoIntegration configureSession(HttpServletRequest request, String usernameKey, String alfTicketKey);

    AlfrescoIntegration configureSession(HttpServletRequest request, HttpServletResponse response, String usernameKey, String alfTicketKey);

    AlfrescoIntegration configureSession(HttpServletRequest request, HttpServletResponse response,HttpSession session, String usernameKey, String alfTicketKey);

    AlfrescoIntegration  setConnectorService(ConnectorService connectorService);

    AlfrescoIntegration  setSession(jakarta.servlet.http.HttpSession session);

    public jakarta.servlet.http.HttpSession  getSession();

    AlfrescoIntegration setRequest(jakarta.servlet.http.HttpServletRequest request);

    public jakarta.servlet.http.HttpServletRequest  getRequest();

    AlfrescoIntegration setResponse(jakarta.servlet.http.HttpServletResponse response);

    public jakarta.servlet.http.HttpServletResponse  getResponse();
    public ConnectorService  getConnectorService();

    public ConnectorService  getConnectorService(ApplicationContext context,String beanId);

    public ConnectorService  getConnectorService(ApplicationContext context);

    AlfrescoIntegration getInstance();

    AlfrescoIntegration initUser(HttpServletRequest request) throws UserFactoryException;

    AlfrescoIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response) throws RequestContextException;

    AlfrescoIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response,HttpSession session) throws  RequestContextException;

    Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
