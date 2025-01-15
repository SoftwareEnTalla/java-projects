package cu.entalla.udi;

import cu.entalla.model.TokenResponseModel;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.function.Function;

public interface ClientServiceIntegration {
    String getTicket(String sessionId, String username, String accessToken);

    ApplicationContext getApplicationContext();

    ClientServiceIntegration setApplicationContext(ApplicationContext context);
    String getTicket(String accessToken);
    ClientServiceIntegration configureSession(HttpSession session, String username, String ticket);

    ClientServiceIntegration configureSession(HttpServletRequest request, String usernameKey, String ticketKey);

    ClientServiceIntegration configureSession(HttpServletRequest request, HttpServletResponse response, String usernameKey, String ticketKey);

    ClientServiceIntegration configureSession(HttpServletRequest request, HttpServletResponse response, HttpSession session, String usernameKey, String ticketKey);

    ClientServiceIntegration setConnectorService(ConnectorService connectorService);

    ClientServiceIntegration setSession(jakarta.servlet.http.HttpSession session);

    public jakarta.servlet.http.HttpSession  getSession();

    ClientServiceIntegration setRequest(jakarta.servlet.http.HttpServletRequest request);

    public jakarta.servlet.http.HttpServletRequest  getRequest();

    ClientServiceIntegration setResponse(jakarta.servlet.http.HttpServletResponse response);

    public jakarta.servlet.http.HttpServletResponse  getResponse();
    public ConnectorService  getConnectorService();

    public ConnectorService  getConnectorService(ApplicationContext context,String beanId);

    public ConnectorService  getConnectorService(ApplicationContext context);

    ClientServiceIntegration getInstance();

    ClientServiceIntegration initUser(HttpServletRequest request) throws UserFactoryException;

    ClientServiceIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response) throws RequestContextException;

    ClientServiceIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws  RequestContextException;

    Authentication authenticate(Function<Object, Authentication> processor,Object obj) throws AuthenticationException;

    public Authentication getAutentication();

    ClientServiceIntegration setAutentication(Authentication autentication);
}
