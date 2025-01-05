package cu.entalla.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.surf.mvc.LogoutController;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.web.servlet.ModelAndView;

public class SlingshotLogoutController extends LogoutController {
    private static final Log logger = LogFactory.getLog(SlingshotLogoutController.class);
    protected ConnectorService connectorService;

    public SlingshotLogoutController() {
    }

    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    public ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                String userId = (String)session.getAttribute("_alf_USER_ID");
                if (userId != null) {
                    Connector connector = this.connectorService.getConnector("alfresco", userId, session);
                    String ticket = connector.getConnectorSession().getParameter("alfTicket");
                    if (ticket != null) {
                        Response res = connector.call("/api/login/ticket/" + ticket, new ConnectorContext(HttpMethod.DELETE));
                        if (logger.isDebugEnabled()) {
                            logger.debug("Expired ticket: " + ticket + " user: " + userId + " - status: " + res.getStatus().getCode());
                        }
                    }
                }
            }
        } finally {
            return super.handleRequestInternal(request, response);
        }
    }
}