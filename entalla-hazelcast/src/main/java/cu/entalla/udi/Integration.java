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

public interface Integration {
    String getTicket(String sessionId, String username, String accessToken);

    ApplicationContext getApplicationContext();

    Integration setApplicationContext(ApplicationContext context);
    String getTicket(String accessToken);
    Integration configureSession(HttpSession session, String username, String ticket);

    Integration configureSession(HttpServletRequest request, String usernameKey, String ticketKey);

    Integration configureSession(HttpServletRequest request, HttpServletResponse response, String usernameKey, String ticketKey);

    Integration configureSession(HttpServletRequest request, HttpServletResponse response, HttpSession session, String usernameKey, String ticketKey);

    Integration setConnectorService(ConnectorService connectorService);

    Integration setSession(jakarta.servlet.http.HttpSession session);

    public jakarta.servlet.http.HttpSession  getSession();

    Integration setRequest(jakarta.servlet.http.HttpServletRequest request);

    public jakarta.servlet.http.HttpServletRequest  getRequest();

    Integration setResponse(jakarta.servlet.http.HttpServletResponse response);

    public jakarta.servlet.http.HttpServletResponse  getResponse();
    public ConnectorService  getConnectorService();

    public ConnectorService  getConnectorService(ApplicationContext context,String beanId);

    public ConnectorService  getConnectorService(ApplicationContext context);

    Integration getInstance();

    Integration initUser(HttpServletRequest request) throws UserFactoryException;

    Integration initRequestContext(HttpServletRequest request, HttpServletResponse response) throws RequestContextException;

    Integration initRequestContext(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws  RequestContextException;

    Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
