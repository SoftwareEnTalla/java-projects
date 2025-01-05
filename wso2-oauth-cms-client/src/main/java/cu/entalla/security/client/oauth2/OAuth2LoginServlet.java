package cu.entalla.security.client.oauth2;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.exception.EmptyOpenIdConfigurationException;
import cu.entalla.exception.EmptyWso2AuthenticatorClient;
import cu.entalla.model.UserProfile;
import cu.entalla.service.UserService;
import cu.entalla.service.AuthenticationService;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.store.CookieManager;
import cu.entalla.util.AccessTokenValidator;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.logging.Logger;

@WebServlet("/wso2/oauth2/login")
public class OAuth2LoginServlet extends HttpServlet {

    private ClientRegistrationRepository clientRegistrationRepository;
    private Wso2SecurityConfig wso2SecConfig =new Wso2SecurityConfig();
    private AuthenticationService authService=new AuthenticationService();

    private  Wso2AuthenticatorClient client;
    private ApplicationContext context;


    private static final Logger logger = Logger.getLogger(OAuth2LoginServlet.class.getName());
    private static String redirectPage="/alfresco";

    public static String getRedirectPage(){
        return redirectPage;
    }
    public OAuth2LoginServlet() {

    }
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.inicializeConfig();
        redirectPage=config.getInitParameter("redirectPage");
        if(redirectPage==null||redirectPage!=null && !redirectPage.isEmpty())
            redirectPage="/alfresco";
        ClientRegistrationRepository clientRegistration = this.wso2SecConfig.clientRegistrationRepository();
        AuthenticationStore.getInstance().setClientRegistrationRepository(clientRegistrationRepository=clientRegistration);
        this.authService = new AuthenticationService();
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(config.getServletContext());

        try {
            SpringContextHolder.setApplicationContext(redirectPage,webApplicationContext);
            SpringContextHolder.registry(redirectPage,webApplicationContext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.context=webApplicationContext;
        this.authService = new AuthenticationService();
    }
    public Wso2SecurityConfig inicializeConfig(){
        this.wso2SecConfig=Wso2SecurityConfig.create().loadProperties();
        client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
        AuthenticationService authService=new AuthenticationService(client);
        AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
        return this.wso2SecConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {

        CookieManager manager=  CookieManager.getInstance().setRequest(req).setResponse(resp);

        String accessToken = manager.getParameter("X-Access-Token")!=null?manager.getParameter("X-Access-Token"):(manager.hasAttribute("X-Access-Token")?manager.getAttribute("X-Access-Token").toString():null);
        String providerId = manager.getParameter("providerId");
        providerId=providerId!=null && !providerId.isEmpty()?providerId:"wso2";
        boolean validAccessToken = AccessTokenValidator.isValidAccessToken(accessToken);
        
        Object globalProperty = manager.getAttribute("globalProperty");
        if (globalProperty != null) {
            this.wso2SecConfig.loadProperties(globalProperty.toString());
        }
        String appBaseUrl=this.wso2SecConfig.extractBaseURL(this.wso2SecConfig.getRedirectUri());
        // Generar Code Verifier y Code Challenge
        String codeVerifier = this.wso2SecConfig.generateCodeVerifier();
        String codeChallenge = this.wso2SecConfig.generateCodeChallenge(codeVerifier);

        // Almacenar el code_verifier en la sesión del usuario
        manager.setAttribute("code_verifier", codeVerifier,true);

        String uri = manager.getRequestURI();
        boolean isAuthenticated=authService.isAuthenticated(manager.getRequest());
        logger.info("isAuthenticated:"+isAuthenticated);
        // Si el usuario no está autenticado y está en la URL de login, iniciar el flujo de PAR
        if ((!validAccessToken || !isAuthenticated) && ((uri.startsWith(redirectPage+"/wso2/oauth2/login") || uri.startsWith(redirectPage+"/wso2/oauth2/login")) )) {
            // Generar el request_uri utilizando PAR
            try {
                manager.setAttribute("X-Alfresco-Remote-User",null,true);
                manager.setAttribute("X-Access-Token",null,true);
                ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId(providerId);
                logger.info("getAutorizationUri:"+providerId);
                // Obtener el request_uri usando PAR
                //String requestUri = authService.getRequestUriUsingPAR(clientRegistration, codeChallenge);
                // Redirigir al proveedor de identidad con el request_uri
                String authorizationUri =this.authService.getAutorizationUri(providerId);
                logger.info("authorizationUri:"+authorizationUri);
                manager.sendRedirect(authorizationUri);
                return;
            } catch (Exception e) {
                e.printStackTrace();
                manager.setAttribute("X-Alfresco-Remote-User",null,true);
                manager.setAttribute("X-Access-Token",null,true);
                manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error al obtener el request_uri utilizando PAR: " + e.getMessage());
                return;
            }
        }

        // Si el usuario ya está autenticado y está en la URL de login, proceder con el flujo de autorización
        if ((validAccessToken && isAuthenticated) && ((uri.startsWith(redirectPage+"/wso2/oauth2/login") || uri.startsWith(redirectPage+"/wso2/oauth2/login")) )) {
            String code = req.getParameter("code");
            if (code == null) {
                manager.setAttribute("X-Alfresco-Remote-User",null,true);
                logger.info("Iniciando flujo de autenticación:"+code);
                inicializeConfig();
                Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
                AuthenticationService authService=new AuthenticationService(client);
                try {
                    authService.authenticationWithCodeFlow(providerId);
                } catch (EmptyOpenIdConfigurationException e) {
                    throw new RuntimeException(e);
                } catch (EmptyWso2AuthenticatorClient e) {
                    throw new RuntimeException(e);
                }
            }

            try {
                // Obtener el token de acceso
               // OAuth2AccessTokenResponse tokenResponse =
                logger.info("getCustomAccessToken with code:"+code);
                accessToken=accessToken==null?authService.getCustomAccessToken(code):accessToken;
                validAccessToken = AccessTokenValidator.isValidAccessToken(accessToken);
                if(!validAccessToken) {
                    manager.setAttribute("X-Alfresco-Remote-User",null,true);
                    manager.setAttribute("X-Access-Token",null,true);
                    manager.sendRedirect(redirectPage);
                }
                manager.setAttribute("X-Access-Token",accessToken,true);
                // Extraer información del usuario desde el token
                Map<String, Object> userInfo = authService.getUserInfo(accessToken);
                UserProfile profile=UserProfile.fromJson(authService.getUserInfoAsString(userInfo));
                AuthenticationStore.getInstance().setUserProfile(profile);
                logger.info("UserInfo:"+profile.toJson());
                // Extraer claims relevantes
                String username = (String) userInfo.get("username");
                manager.setAttribute("X-Alfresco-Remote-User",username,true);
                String email = (String) userInfo.get("email");
                String phone = (String) userInfo.get("phone_number");
                logger.info("Usuario autenticándose:"+username+" email:"+email+" phone:"+phone);
                logger.info("Usuario "+username+" autenticado. Redireccionando hacia:"+appBaseUrl+"/alfresco");

                Cookie usernameCookie = new Cookie("X-Alfresco-Remote-User", username);
                usernameCookie.setPath("/alfresco");
                usernameCookie.setHttpOnly(true);
                manager= manager.addCookie(usernameCookie);


               /* Cookie tokenCookie = new Cookie("X-Access-Token", accessToken);
                tokenCookie.setPath("/alfresco");
                tokenCookie.setHttpOnly(true);
                manager.addCookie(tokenCookie);*/

                usernameCookie = new Cookie("X-Alfresco-Remote-User", username);
                usernameCookie.setPath("/share");
                usernameCookie.setHttpOnly(true);
                manager.addCookie(usernameCookie);

               /* tokenCookie = new Cookie("X-Access-Token", accessToken);
                tokenCookie.setPath("/share");
                tokenCookie.setHttpOnly(true);
                manager.addCookie(tokenCookie);*/

                manager.setHeader("X-Alfresco-Remote-User", username,true);
                //manager.setHeader("X-Access-Token", accessToken,true);

                manager.setAttribute("X-Alfresco-Remote-User", username,true);
                manager.setAttribute("X-Access-Token", accessToken,true);
                // Redirigir al usuario a Alfresco
                manager.sendRedirect(redirectPage+"?code="+ URLEncoder.encode(code, "UTF-8"));

            } catch (Exception e) {
                manager.setAttribute("X-Alfresco-Remote-User",null,true);
                manager.setAttribute("X-Access-Token",null,true);
                manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to authenticate: " + e.getMessage());
            }
            return;
        }
    }

}
