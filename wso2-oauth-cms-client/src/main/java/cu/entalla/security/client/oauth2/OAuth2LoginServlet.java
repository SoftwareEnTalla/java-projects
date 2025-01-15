package cu.entalla.security.client.oauth2;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.exception.EmptyOpenIdConfigurationException;
import cu.entalla.exception.EmptyWso2AuthenticatorClient;
import cu.entalla.model.UserProfile;
import cu.entalla.security.AuthenticationException;
import cu.entalla.security.SecurityUtils;
import cu.entalla.security.client.oauth2.authentication.TicketAuthentication;
import cu.entalla.service.ServiceLocator;
import cu.entalla.service.AuthenticationService;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.store.CookieManager;
import cu.entalla.udi.ClientServiceIntegration;
import cu.entalla.util.AccessTokenValidator;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

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
        this.authorizationRequestRepository=new HttpSessionOAuth2AuthorizationRequestRepository();
        redirectPage=config.getInitParameter("redirectPage");
        if(redirectPage==null||redirectPage!=null && !redirectPage.isEmpty())
            redirectPage="/alfresco";
        ClientRegistrationRepository clientRegistration = this.wso2SecConfig.clientRegistrationRepository();
        AuthenticationStore.getInstance().setClientRegistrationRepository(clientRegistrationRepository=clientRegistration);
        this.authService = new AuthenticationService();
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(config.getServletContext());
        try {
            SpringContextHolder.setApplicationContext(redirectPage,webApplicationContext);
            this.wso2SecConfig.getIntegrator();
            //SpringContextHolder.registry(redirectPage,webApplicationContext);
        } catch (Exception e) {
            logger.severe(":::::::::::: ERROR ejecutando OAuth2LoginServlet->init ::::::::::::\n"+e.getMessage());
            throw new RuntimeException(e);
        }
        this.context=webApplicationContext;
        if(this.authService==null)
            this.authService = new AuthenticationService();
    }
    public Wso2SecurityConfig inicializeConfig(){
        if(this.wso2SecConfig==null){
        this.wso2SecConfig=Wso2SecurityConfig.create().loadProperties();
        client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
        this.authService=new AuthenticationService(client);
        AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
        return this.wso2SecConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        }
        client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
        this.authService=new AuthenticationService(client);
        return this.wso2SecConfig;
    }
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        this.authorizationRequestRepository=new HttpSessionOAuth2AuthorizationRequestRepository();

        // Cargar configuración
        this.inicializeConfig();
        // Inicializar el gestor de cookies
        CookieManager manager = CookieManager.getInstance().setRequest(req).setResponse(resp);
        String uri = manager.getRequestURI();
        String appBaseUrl = this.wso2SecConfig.extractBaseURL(this.wso2SecConfig.getRedirectUri());
        SecurityUtils util = new SecurityUtils();
        String requestPage=uri.split("/")[1];
        String tmp= manager.getCookieValueByName("X-Redirect");
        redirectPage=tmp!=null?tmp:redirectPage;
        if(requestPage!=requestPage)
            requestPage=requestPage;
        req.setAttribute("X-Redirect",redirectPage);
        client.setServletResponse(resp);
        client.setServletRequest(req);
        // Validar parámetros
        String providerId = manager.getParameter("providerId");
        providerId = (providerId != null && !providerId.isEmpty()) ? providerId : "wso2";

        // Obtener AccessToken desde la cookie
        String accessToken = manager.getCookieValueByName("X-Access-Token");
        if (accessToken == null || accessToken.isEmpty()) {
            logger.warning("AccessToken no encontrado en las cookies.");
            //manager.sendError(HttpServletResponse.SC_UNAUTHORIZED, "AccessToken no encontrado.");
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
            client.setServletRequest(req);
            client.setServletResponse(resp);
            AuthenticationService authService = new AuthenticationService(client);
            try {
                authService.authenticationWithCodeFlow(providerId);
            } catch (EmptyOpenIdConfigurationException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (EmptyWso2AuthenticatorClient e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            return;
        }
        logger.info("AccessToken from Cookie: " + accessToken);
        // Obtener información del usuario desde la cookie
        String userLogued = manager.getCookieValueByName(wso2SecConfig.getAuthenticatedUserKeyWord());
        Object userOnSession = req.getSession().getAttribute(wso2SecConfig.getAuthenticatedUserKeyWord());
        String userFromAccessToken = null;

        try {
            userFromAccessToken = util.getUsernameFromToken(accessToken);
        } catch (AuthenticationException ex) {
            logger.warning("Error al obtener usuario desde AccessToken: " + ex.getMessage());
        }
        // Validar AccessToken
        boolean validAccessToken = AccessTokenValidator.isValidAccessToken(accessToken);
        // Verificar si el usuario está autenticado
        boolean isAuthenticated = validAccessToken
                && userFromAccessToken != null
                && userFromAccessToken.equals(userLogued)
                && authService.isAuthenticated(userLogued,accessToken);

        if (userOnSession == null && isAuthenticated) {
            req.getSession().setAttribute(wso2SecConfig.getAuthenticatedUserKeyWord(), userOnSession=userLogued);
            manager = manager.setRequest(req);
        }

        boolean startWithAlfresco=uri.startsWith("/alfresco/wso2/oauth2/login");
        boolean startWithShare=uri.startsWith("/share/wso2/oauth2/login");
        logger.info("User userLogued : " + userLogued);
        logger.info("User exists on session: " + (userOnSession != null));
        logger.info("User is Authenticated: " + isAuthenticated);
        logger.info("AccessToken is Valid: " + validAccessToken);
        logger.info("AppBaseUrl: " + appBaseUrl);
        logger.info("URI: " + uri);
        logger.info("redirectPage: " + redirectPage);
        logger.info("uri.startsWith(/alfresco/wso2/oauth2/login"+"): " + startWithAlfresco);
        logger.info("uri.startsWith(/share/wso2/oauth2/login"+"): " + startWithShare);
        // Flujo autenticado
        if ((validAccessToken && isAuthenticated) && (startWithAlfresco||startWithShare)) {
            String code = req.getParameter("code")!=null?req.getParameter("code"):manager.getCookieValueByName("X-Code");
            logger.info("ValidAccessToken and isAuthenticated are true with code="+code);
            if (code == null) {
                manager = manager.setAttribute(wso2SecConfig.getAuthenticatedUserKeyWord(), null, true);
                logger.info("Iniciando flujo de autenticación");
                try {
                    Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
                    client.setServletRequest(req);
                    client.setServletResponse(resp);
                    AuthenticationService authService = new AuthenticationService(client);
                    authService.authenticationWithCodeFlow(providerId);
                } catch (Exception e) {
                    logger.severe("Error iniciando flujo de autenticación: " + e.getMessage());
                    manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error de autenticación: " + e.getMessage());
                    return;
                }
            }

            try {
                // Extraer información del usuario
                logger.info("Buscando información del usuario:"+userLogued);
                Map<String, Object> userInfo = authService.getUserInfo(accessToken);
                UserProfile profile = UserProfile.fromJson(authService.getUserInfoAsString(userInfo));
                logger.info("UserInfo: " + profile.toJson());

                // Configurar cookies para Alfresco y Share
                String username = (String) userInfo.get("username");
                logger.info("::::::::::::::ClientServiceIntegration::::::::::::::::::::::");
                ClientServiceIntegration integration=ServiceLocator.getIntegrator()
                        .setSession(req.getSession())
                        .setRequest(req)
                        .setResponse(resp)
                       .initRequestContext(req,resp);
                logger.info(":::::::::::::: ClientServiceIntegration->initRequestContext ::::::::::::::::::::::");
                String mode=wso2SecConfig.getPropertyByKey("oauth2.client.provider.wso2.ticket-mode","standar");
                logger.info(":::::::::::::: Ticket->Mode="+mode+" ::::::::::::::::::::::");
                String ticket="custom".equals(mode) ?integration.getTicket(accessToken):integration.getTicket(req.getSession().getId(),username,accessToken);
                logger.info(":::::::::::::: Ticket->Value="+ticket+" ::::::::::::::::::::::");
                ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
                logger.info("clientRegistration: " + clientRegistration);
                String sessionState =  wso2SecConfig.getSessionState();
                if(sessionState==null){
                    wso2SecConfig.setSessionState(sessionState=UUID.randomUUID().toString());
                }
                req.getSession().setAttribute("session_state",sessionState);
                OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(req, resp);
                if(authorizationRequest==null) {
                  authorizationRequest= OAuth2AuthorizationRequest.authorizationCode()
                            .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                            .clientId(clientRegistration.getClientId())
                            .redirectUri(clientRegistration.getRedirectUri())
                            .scope(clientRegistration.getScopes().stream().collect(Collectors.joining()).split(" "))
                            .state(sessionState)
                            .build();
                    authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest,req,resp);
                }

                OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
                        .success(code)
                        .state(sessionState)
                        .redirectUri(clientRegistration.getRedirectUri())
                        .build();

                OAuth2AuthorizationExchange exchange = new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);

                Authentication authentication = new TicketAuthentication(
                        clientRegistration,
                        exchange,
                        accessToken,
                        ticket,
                        username,
                        Arrays.asList(new SimpleGrantedAuthority("GROUP_EVERYONE"),new SimpleGrantedAuthority("GROUP_AUTHENTICATED")),
                        userInfo
                );
                logger.info(":::::::::::::: Authentication builded:"+(authentication!=null));
                logger.info(":::::::::::::: ClientServiceIntegration->configureSession(req.getSession(),username,ticket) ::::::::::::::::::::::");
                integration=integration.configureSession(req.getSession(),username,ticket);
                logger.info(":::::::::::::: ClientServiceIntegration->authenticate(authentication)::::::::::::::::::::::");
                Authentication finalAuthentication = authentication;
                boolean finalIsAuthenticated = isAuthenticated;
                authentication=integration.authenticate((pro)->{
                    finalAuthentication.setAuthenticated(ticket!=null && finalIsAuthenticated);
                    return finalAuthentication;
                },this);
                if(authentication!=null) {
                    boolean isOk = authentication.isAuthenticated();
                    logger.info(":::::::::::::: ClientServiceIntegration->isAuthenticated()=" + isOk + "::::::::::::::::::::::");
                }
                else {
                    logger.severe(":::::::::::::: ClientServiceIntegration->isAuthenticated()=failed becouse authentication is null");
                }

                Cookie usernameCookie = new Cookie(wso2SecConfig.getAuthenticatedUserKeyWord(), username);
                usernameCookie.setPath("/");
                usernameCookie.setHttpOnly(true);
                manager = manager.addCookie(usernameCookie);

                usernameCookie = new Cookie(wso2SecConfig.getAuthenticatedUserKeyWord(), username);
                usernameCookie.setPath("/");
                usernameCookie.setHttpOnly(true);
                manager = manager.addCookie(usernameCookie);

                Cookie atoken = new Cookie("X-Access-Token", accessToken);
                atoken.setPath("/");
                atoken.setHttpOnly(true);
                manager = manager.addCookie(atoken);

                atoken = new Cookie("X-Access-Token", accessToken);
                atoken.setPath("/");
                atoken.setHttpOnly(true);
                manager = manager.addCookie(atoken);

                Cookie ticketCookie = new Cookie("Alfresco-Ticket", ticket);
                ticketCookie.setPath("/");
                manager.addCookie(ticketCookie);

                manager = manager.addCookie(new Cookie("X-Redirect", redirectPage));

                manager = manager.setAttribute("Alfresco-Ticket",ticket,true);
                manager = manager.setAttribute("X-Access-Token", accessToken, true);
                manager = manager.setAttribute(wso2SecConfig.getAuthenticatedUserKeyWord(), username, true);
                logger.info("----------- Code:"+code+"-------------- Ticket"+ticket);
                logger.info("----------- Rediret to:"+(appBaseUrl + redirectPage)+"-------------- ");
                String tmpTicket=ticket!=null && !ticket.isEmpty()?"&alf_ticket="+ URLEncoder.encode(ticket, "UTF-8"):"";
                String tmpCode=code!=null && !code.isEmpty()?"code=" + URLEncoder.encode(code, "UTF-8"):"";
                // Redirigir al usuario
                if (!resp.isCommitted())
                    manager.sendRedirect(appBaseUrl + redirectPage + "?" +tmpCode+tmpTicket);
            } catch (Exception e) {
                req.getSession().getAttributeNames().asIterator().forEachRemaining((el->{
                    req.getSession().removeAttribute(el);
                }));
                manager.setRequest(req);
                //logger.severe("Error manejando el flujo de autenticación: " + e.getMessage());
                e.printStackTrace();
               // if (!resp.isCommitted())
               //      manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to authenticate: " + e.getMessage());
                validAccessToken=false;
                isAuthenticated=false;
            }
           // return;
        }

        // Flujo no autenticado
        if ((!validAccessToken || !isAuthenticated) && uri.startsWith(redirectPage + "/wso2/oauth2/login")) {
            try {
                String authorizationUri = this.authService.getAutorizationUri(providerId);
                logger.info("Authorization URI: " + authorizationUri);
                manager.sendRedirect(authorizationUri);
            } catch (Exception e) {
                logger.severe("Error generando la URL de autorización: " + e.getMessage());
                manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error en el flujo de autorización: " + e.getMessage());
            }
        }
    }
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();

    private final GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> {
        return authorities;
    };
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcUserService();
    private OidcIdToken createOidcToken(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
        JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(clientRegistration);

        Jwt jwt=null;
        try {
            jwt = jwtDecoder.decode((String)accessTokenResponse.getAdditionalParameters().get("id_token"));
        } catch (JwtException var7) {
            OAuth2Error invalidIdTokenError = new OAuth2Error("invalid_id_token", var7.getMessage(), (String)null);
            throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), var7);
        }
        OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
        return idToken;
    }

    static String createHash(String nonce) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
    public Authentication authenticate(Authentication authentication) throws org.springframework.security.core.AuthenticationException {
        OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken)authentication;
        if (!authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
            return null;
        } else {
            OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest();
            OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationResponse();
            if (authorizationResponse.statusError()) {
                throw new OAuth2AuthenticationException(authorizationResponse.getError(), authorizationResponse.getError().toString());
            } else if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
                OAuth2Error oauth2Error = new OAuth2Error("invalid_state_parameter");
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            } else {
                OAuth2AccessTokenResponse accessTokenResponse;
                try {
                    accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange()));
                } catch (OAuth2AuthorizationException var14) {
                    OAuth2Error oauth2Error = var14.getError();
                    throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                }

                ClientRegistration clientRegistration = authorizationCodeAuthentication.getClientRegistration();
                Map<String, Object> additionalParameters = accessTokenResponse.getAdditionalParameters();
                if (!additionalParameters.containsKey("id_token")) {
                    OAuth2Error invalidIdTokenError = new OAuth2Error("invalid_id_token", "Missing (required) ID Token in Token Response for Client Registration: " + clientRegistration.getRegistrationId(), (String)null);
                    throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
                } else {
                    OidcIdToken idToken = this.createOidcToken(clientRegistration, accessTokenResponse);
                    String requestNonce = (String)authorizationRequest.getAttribute("nonce");
                    if (requestNonce != null) {
                        String nonceHash;
                        OAuth2Error oauth2Error;
                        try {
                            nonceHash = createHash(requestNonce);
                        } catch (NoSuchAlgorithmException var13) {
                            oauth2Error = new OAuth2Error("invalid_nonce");
                            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                        }

                        String nonceHashClaim = idToken.getNonce();
                        if (nonceHashClaim == null || !nonceHashClaim.equals(nonceHash)) {
                            oauth2Error = new OAuth2Error("invalid_nonce");
                            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                        }
                    }

                    OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration, accessTokenResponse.getAccessToken(), idToken, additionalParameters));
                    Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
                    OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oidcUser, mappedAuthorities, accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken());
                    authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
                    return authenticationResult;
                }
            }
        }
    }

}
