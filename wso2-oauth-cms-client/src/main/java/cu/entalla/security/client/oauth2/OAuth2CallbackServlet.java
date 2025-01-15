package cu.entalla.security.client.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.model.AuthorizationResponseModel;
import cu.entalla.model.UserProfile;
import cu.entalla.security.SecurityUtils;
import cu.entalla.service.AuthenticationService;
import cu.entalla.service.ServiceLocator;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.store.CookieManager;
import cu.entalla.util.AccessTokenValidator;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@WebServlet("/wso2/oauth2/callback")
public class OAuth2CallbackServlet extends HttpServlet {

    private ClientRegistrationRepository clientRegistrationRepository;
    private Wso2SecurityConfig wso2SecConfig =new Wso2SecurityConfig();
    private AuthenticationService authService=new AuthenticationService();

    Map<String, Object> additionalParameters = new HashMap<>();

    OAuth2AccessToken oauth2AccessToken;
    private  Wso2AuthenticatorClient client;

    private static final Logger logger = Logger.getLogger(OAuth2CallbackServlet.class.getName());
    private static final Log log = LogFactory.getLog(OAuth2CallbackServlet.class);
    // Constructor sin argumentos requerido por el contenedor

    private ApplicationContext context;
    private boolean enabled = false;
    public static final String CLIENT_ENDPOINT_ID = "alfresco";
    public static final String CLIENT_API_ENDPOINT_ID = "alfresco-api";
    public static final String SHARE_PAGE = "/share/page";
    public static final String SHARE_AIMS_LOGOUT = "/share/page/aims/logout";
    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";

    private OAuth2AuthorizedClientService oauth2ClientService;
    private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private RequestCache requestCache= new HttpSessionRequestCache();

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    private final DefaultRefreshTokenTokenResponseClient refreshTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
    private ThrowableAnalyzer throwableAnalyzer;
    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();
    private final GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> {
        return authorities;
    };
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcUserService();
    private String clientId;

    private static String redirectPage="/alfresco";

    public static String getRedirectPage(){
        return redirectPage;
    }

    HttpServletRequest request;
    HttpServletResponse response;

    public OAuth2CallbackServlet() {
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
            //this.wso2SecConfig.getIntegrator();
            //SpringContextHolder.registry(redirectPage,webApplicationContext);
        } catch (Exception e) {
            logger.severe(":::::::::::: ERROR ejecutando OAuth2LoginServlet->init ::::::::::::\n"+e.getMessage());
            throw new RuntimeException(e);
        }
        this.context=webApplicationContext;
        this.oauth2ClientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }
    public Wso2SecurityConfig inicializeConfig(){
        if(this.wso2SecConfig==null) {
            this.wso2SecConfig = Wso2SecurityConfig.create().loadProperties();
            client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
            AuthenticationService authService = new AuthenticationService(client);
            AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
            return this.wso2SecConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
        }
        client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
        this.authService=new AuthenticationService(client);
        return this.wso2SecConfig;
    }
    @Override
    protected void doGet(HttpServletRequest  req, HttpServletResponse resp) throws IOException, ServletException {
        this.request=req;
        this.response=resp;
        this.authorizationRequestRepository=new HttpSessionOAuth2AuthorizationRequestRepository();
        this.oauth2ClientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
        ClientRegistrationRepository clientRegistration = this.wso2SecConfig.clientRegistrationRepository();
        AuthenticationStore.getInstance().setClientRegistrationRepository(clientRegistrationRepository=clientRegistration);
        this.clientId=wso2SecConfig.getClientId();
        client.setServletResponse(this.response);
        client.setServletRequest(this.request); String providerId = request.getParameter("providerId");
        providerId = (providerId != null && !providerId.isEmpty()) ? providerId : "wso2";

        this.context=SpringContextHolder.getApplicationContext(redirectPage);
        CookieManager manager= cu.entalla.store.CookieManager.getInstance().setRequest(this.request).setResponse(this.response);
        manager=manager.setSession(this.request.getSession());
        String code = manager.getParameter("code");
        if (code == null) {
            //this.response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No authorization code provided on: "+req.getMethod()+"/"+req.getQueryString());
           // return;
            manager = manager.setAttribute(wso2SecConfig.getAuthenticatedUserKeyWord(), null, true);
            logger.info("Iniciando flujo de autenticación");
            try {
                Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
                client.setServletRequest(request);
                client.setServletResponse(response);
                AuthenticationService authService = new AuthenticationService(client);
                authService.authenticationWithCodeFlow(providerId);
            } catch (Exception e) {
                logger.severe("Error iniciando flujo de autenticación: " + e.getMessage());
                manager.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error de autenticación: " + e.getMessage());
                return;
            }
            return;
        }
        manager=manager.setAttribute("code",code,true);
        inicializeConfig().loadProperties();

        String codeVerifier= null;
        if(wso2SecConfig.isPkceFlow() && manager.getAttribute("code_verifier")!=null){
            codeVerifier= manager.getAttribute("code_verifier").toString();
        }
        String uri = manager.getRequestURI();
        Map<String, String[]> params = manager.getParameterMap();
        logger.info("URL to redirect="+this.wso2SecConfig.getRedirectUri());
        String appBaseUrl=this.wso2SecConfig.extractBaseURL(this.wso2SecConfig.getRedirectUri());
        logger.info("URL appBaseUrl="+appBaseUrl);
        logger.info("RequestUri="+uri);
        if (uri.equals(redirectPage+"/wso2/oauth2/callback")) {
            code = manager.getParameter("code");
            String sessionState = manager.getParameter("session_state");
            this.request.getSession().setAttribute("session_state",sessionState);
            logger.info("CODE="+code);
            logger.info("codeVerifier="+codeVerifier);
            logger.info("wso2SecConfig.isPkceFlow()="+wso2SecConfig.isPkceFlow());
            if (code == null || (codeVerifier == null && wso2SecConfig.isPkceFlow())) {
                 manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid PKCE flow");
                return;
            }
            logger.info("Ending callback for code="+code+" and sessionState="+sessionState);
            AuthorizationResponseModel authorizationResponseModel = client.completeCallback(code, sessionState);
            String accessTokenResponse=null;
            try{
                this.request.getSession().setAttribute("session_state",sessionState);
                OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(this.request, this.response);
                if(authorizationRequest==null) {
                    authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                            .authorizationUri(wso2SecConfig.getAuthorizationUri())
                            .clientId(wso2SecConfig.getClientId())
                            .redirectUri(wso2SecConfig.getRedirectUri())
                            .scope(wso2SecConfig.getScope().split(" "))
                            .state(sessionState.toString())
                            .build();
                    authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest,this.request,this.response);
                }
                accessTokenResponse = codeVerifier!=null && !codeVerifier.isEmpty()? authService.getCustomAccessToken(this.request,code, codeVerifier): authService.getCustomAccessToken(this.request,code);
            }
            catch(Exception e)
            {

            }
            try {
                if(accessTokenResponse==null)
                {
                    manager.sendRedirect(redirectPage+"/wso2/oauth2/login");
                }
                String decoded = authService.decodeToken(accessTokenResponse);
                 // Crear una instancia de OAuth2AccessToken

                logger.info("Decoded AccessTokenResponse:"+decoded);
                ObjectMapper objectMapper = new ObjectMapper();
                Map<String, Object> map = objectMapper.readValue(decoded, Map.class);
                map.put("id_token",request.getSession().getAttribute("id_token"));
                map.put("access_token",accessTokenResponse);
                map.put("refresh_token",request.getSession().getAttribute("refresh_token"));
                // Lista de parámetros estándar a excluir
                Set<String> standardParameters = Set.of(
                        "access_token", "id_token", "expires_in", "scope", "token_type", "refresh_token",
                        "sub", "iss", "aud", "exp", "iat", "nbf", "azp", "jti"
                );
                additionalParameters=new HashMap<>();
                // Extraer los additionalParameters
                for (Map.Entry<String, Object> entry : map.entrySet()) { // Esto es lo correcto
                    if (!standardParameters.contains(entry.getKey())) {
                        additionalParameters.put(entry.getKey(), entry.getValue());
                    }
                }
               map.forEach((k,v)->{
                   logger.info("Atributo:"+k+" valor:"+v.toString());
               });

                oauth2AccessToken = createOAuth2AccessToken(accessTokenResponse,map);
                // Procesar tokenResponse según sea necesario
                // Extraer información del usuario desde el token
                Map<String, Object> userInfo = authService.getUserInfo(accessTokenResponse);
                UserProfile profile=UserProfile.fromJson(authService.getUserInfoAsString(userInfo));
                AuthenticationStore.getInstance().setUserProfile(profile);
                logger.info("UserInfo:"+profile.toJson());
                // Extraer claims relevantes
                String username = (String) userInfo.get("username");
                manager=manager.setAttribute(this.wso2SecConfig.getAuthenticatedUserKeyWord(),username,true);
                manager=manager.setAttribute("X-Access-Token",accessTokenResponse,true);
                String email = (String) userInfo.get("email");
                String phone = (String) userInfo.get("phone_number");
                logger.info("Usuario autenticándose:"+username+" email:"+email+" phone:"+phone);
                logger.info("Usuario "+username+" autenticado. Redireccionando hacia:"+appBaseUrl+"/alfresco");

                Cookie usernameCookie = new Cookie(this.wso2SecConfig.getAuthenticatedUserKeyWord(), username);
                usernameCookie.setPath("/");
                usernameCookie.setHttpOnly(true);
                manager=manager.addCookie(usernameCookie);

                usernameCookie = new Cookie(this.wso2SecConfig.getAuthenticatedUserKeyWord(), username);
                usernameCookie.setPath("/");
                usernameCookie.setHttpOnly(true);
                manager=manager.addCookie(usernameCookie);

                Cookie tokenCookie = new Cookie("X-Access-Token", accessTokenResponse);
                tokenCookie.setPath("/");
                tokenCookie.setHttpOnly(true);
                manager=manager.addCookie(tokenCookie);

                tokenCookie = new Cookie("X-Access-Token", accessTokenResponse);
                tokenCookie.setPath("/");
                tokenCookie.setHttpOnly(true);
                manager=manager.addCookie(tokenCookie);

                Cookie codeCookie = new Cookie("X-Code", code);
                codeCookie.setPath("/");
                codeCookie.setHttpOnly(true);
                manager=manager.addCookie(codeCookie);

                codeCookie = new Cookie("X-Code", code);
                codeCookie.setPath("/");
                codeCookie.setHttpOnly(true);
                manager=manager.addCookie(codeCookie);

                manager = manager.addCookie(new Cookie("X-Redirect", redirectPage));

                manager=manager.setHeader(this.wso2SecConfig.getAuthenticatedUserKeyWord(), username,true);
                manager=manager.setHeader("X-Code", code,true);
                manager=manager.setAttribute("X-Code", code,true);
                //manager.setHeader("X-Access-Token", accessTokenResponse,true);
                //onSuccess(req,resp,req.getSession(),username,accessTokenResponse);
                processAuthorizationResponse(this.request,this.response,this.request.getSession(),true);
                // Redirigir al usuario a Alfresco
                code=code!=null?"code="+URLEncoder.encode(code, "UTF-8"):"";
                logger.info("------------ Method processAuthorizationResponse ended well and redirecting now to: "+(redirectPage+"?"+code+" ---------------------"));
                if (!response.isCommitted())
                    manager.sendRedirect(redirectPage+"?"+code);
            } catch (Exception e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                if (!response.isCommitted())
                 manager.sendRedirect(redirectPage+"/wso2/oauth2/login");
                throw new ServletException(e);
            }

        }

    }

    private boolean matchesAuthorizationResponse(HttpServletRequest request) {
        MultiValueMap<String, String> params = SecurityUtils.toMultiMap(request.getParameterMap());
        if (!SecurityUtils.isAuthorizationResponse(params)) {
            return false;
        } else {
            OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
            if (authorizationRequest == null) {
                return false;
            } else {
                UriComponents requestUri = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).build();
                UriComponents redirectUri = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri()).build();
                Set<Map.Entry<String, List<String>>> requestUriParameters = new LinkedHashSet<>(requestUri.getQueryParams().entrySet());
                Set<Map.Entry<String, List<String>>> redirectUriParameters = new LinkedHashSet(redirectUri.getQueryParams().entrySet());
                requestUriParameters.retainAll(redirectUriParameters);
                return Objects.equals(requestUri.getScheme(), redirectUri.getScheme()) && Objects.equals(requestUri.getUserInfo(), redirectUri.getUserInfo()) && Objects.equals(requestUri.getHost(), redirectUri.getHost()) && Objects.equals(requestUri.getPort(), redirectUri.getPort()) && Objects.equals(requestUri.getPath(), redirectUri.getPath()) && Objects.equals(requestUriParameters.toString(), redirectUriParameters.toString());
            }
        }
    }
    private synchronized void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response, HttpSession session,boolean isAuthenticated) throws IOException {
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
        String sessionState = wso2SecConfig.getSessionState();
        if(authorizationRequest==null) {
            authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri(wso2SecConfig.getAuthorizationUri())
                    .clientId(wso2SecConfig.getClientId())
                    .redirectUri(wso2SecConfig.getRedirectUri())
                    .scope(wso2SecConfig.getScope().split(" "))
                    .state(sessionState)
                    .build();
        }
        MultiValueMap<String, String> params = SecurityUtils.toMultiMap(request.getParameterMap());
        String redirectUri = UrlUtils.buildFullRequestUrl(request);
        OAuth2AuthorizationResponse authorizationResponse = SecurityUtils.convert(params, redirectUri);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(this.clientId);
        if(clientRegistration==null){
            this.clientRegistrationRepository=wso2SecConfig.clientRegistrationRepository();
            clientRegistration= this.clientRegistrationRepository.findByRegistrationId("wso2");
        }

        OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        authenticationRequest.setAuthenticated(isAuthenticated);
        OAuth2LoginAuthenticationToken authenticationResult;
        try {
            authenticationResult = (OAuth2LoginAuthenticationToken)this.authenticate(authenticationRequest);
        } catch (OAuth2AuthorizationException var16) {
            OAuth2Error error = var16.getError();
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri()).queryParam("error", new Object[]{error.getErrorCode()});
            if (!StringUtils.isEmpty(error.getDescription())) {
                uriBuilder.queryParam("error_description", new Object[]{error.getDescription()});
            }

            if (!StringUtils.isEmpty(error.getUri())) {
                uriBuilder.queryParam("error_uri", new Object[]{error.getUri()});
            }
            this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
            return;
        } catch (ParseException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(authenticationResult);
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        String principalName = currentAuthentication != null ? currentAuthentication.getPrincipal().toString() : "anonymousUser";
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(authenticationResult.getClientRegistration(), principalName, authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
        this.oauth2ClientService.saveAuthorizedClient(authorizedClient, currentAuthentication);
        String redirectUrl = authorizationRequest.getRedirectUri();
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        if (SecurityContextHolder.getContext() != null && !AuthenticationUtil.isAuthenticated(request)) {
            ServiceLocator.getIntegrator().setAutentication(authenticationRequest).getAutentication().setAuthenticated(true);
            this.onSuccess(request, response, session, authenticationResult);
        }
        if (savedRequest != null) {
            redirectUrl = savedRequest.getRedirectUrl();
            this.requestCache.removeRequest(request, response);
        }
        this.redirectStrategy.sendRedirect(request, response, redirectUrl);
    }
    private void onSuccess(HttpServletRequest request, HttpServletResponse response, HttpSession session,String username, String accessToken) {
        if (log.isInfoEnabled()) {
            log.info("Completing the WSO2 authentication.");
        }
        configureSession(request,response,session,username,accessToken);
        session.setAttribute("onSuccess",true);
    }
    private void configureSession(HttpServletRequest request, HttpServletResponse response, HttpSession session,String username, String accessToken){
        synchronized (this) {
            try {
                if(this.context==null){
                    logger.info("Inicializando contexto");
                    SpringContextHolder.setApplicationContext(redirectPage,WebApplicationContextUtils.getWebApplicationContext(request.getServletContext()));
                    this.context=SpringContextHolder.getApplicationContext(redirectPage);
                    session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to complete WSO2 authentication process.", e);
            }
        }
    }
    private void onSuccess(HttpServletRequest request, HttpServletResponse response, HttpSession session, OAuth2LoginAuthenticationToken authenticationResult) {
        if (log.isInfoEnabled()) {
            log.info("Completing the WSO2 authentication.");
        }
        try {
            authenticationResult.setAuthenticated(true);
            String username = (String)authenticationResult.getPrincipal().getAttribute("username");
            String accessToken = authenticationResult.getAccessToken().getTokenValue();
            configureSession(request,response,session,username,accessToken);
            ServiceLocator.getIntegrator().setAutentication(authenticationResult).getAutentication().setAuthenticated(true);
        } catch (Exception e) {
            throw new RuntimeException("Failed to complete WSO2 authentication process.", e);
        }

    }
    private void initUser(HttpServletRequest request) throws UserFactoryException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (context != null && context.getUser() == null) {
            String userEndpointId = (String)context.getAttribute("alfUserEndpoint");
            UserFactory userFactory = context.getServiceRegistry().getUserFactory();
            org.springframework.extensions.webscripts.connector.User user = userFactory.initialiseUser(context, request, userEndpointId);
            context.setUser(user);
        }

    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException, MalformedURLException, ParseException, JOSEException {
        OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken)authentication;

        if(!authentication.isAuthenticated()){
            if (!authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
                return null;
            } else {
                OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest();
                OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationResponse();
                logger.info("-------------------- authorizationResponse.getState()="+authorizationResponse.getState()+" and authorizationRequest.getState()="+authorizationRequest.getState()+"-------------");
                if (authorizationResponse.statusError()) {
                    throw new OAuth2AuthenticationException(authorizationResponse.getError(), authorizationResponse.getError().toString());
                } else if ( !authorizationResponse.getState().equals(authorizationRequest.getState())) {
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
                        OidcIdToken idToken = this.authService.createOidcToken(clientRegistration,accessTokenResponse.getAccessToken().getTokenValue());
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
        else {
            OidcIdToken idToken = this.authService.getOidcIdToken();
            Object refreshToken=request.getSession().getAttribute("refresh_token");
            OAuth2RefreshToken oAuth2RefreshToken = new OAuth2RefreshToken(refreshToken != null ? refreshToken.toString() : null, Instant.now());
            ClientRegistration clientRegistration= this.clientRegistrationRepository.findByRegistrationId("wso2");
            OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration,oauth2AccessToken, idToken, additionalParameters));
            Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
            OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oidcUser, mappedAuthorities, oauth2AccessToken, oAuth2RefreshToken);
            authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
            return authenticationResult;
        }
    }
    private  OAuth2AccessToken createOAuth2AccessToken(String tokenValue,Map<String, Object> map) {
        String exp = map.get("exp").toString();
        // Crear el OAuth2AccessToken
        OAuth2AccessToken.TokenType tokenType = OAuth2AccessToken.TokenType.BEARER; // El tipo de token, por lo general es BEARER
        Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(exp)); // El valor de expiración del token
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put("sub", map.get("sub"));
        additionalParameters.put("email", map.get("email"));
        additionalParameters.put("username", map.get("username"));
        additionalParameters.put("iat", map.get("iat"));
        additionalParameters.put("aud", map.get("aud"));
        // Otros claims adicionales pueden ser agregados aquí
        String scopes=wso2SecConfig.getScope();
        // Crear y devolver el OAuth2AccessToken
        return new OAuth2AccessToken(tokenType, tokenValue, Instant.now(), expiresAt, Arrays.stream(scopes.split(" ")).collect(Collectors.toSet()));
    }

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

    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response, OAuth2AuthorizationRequest authorizationRequest) throws IOException {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
            this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
        }

        this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
    }

    private void unsuccessfulRedirectForAuthorization(HttpServletResponse response) throws IOException {
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    }

    private synchronized void refreshToken(SecurityContext attribute, HttpSession session) throws MalformedURLException, ParseException, JOSEException {
        OAuth2LoginAuthenticationToken oAuth2LoginAuthenticationToken = (OAuth2LoginAuthenticationToken)attribute.getAuthentication();
        ClientRegistration clientRegistration = oAuth2LoginAuthenticationToken.getClientRegistration();
        OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(clientRegistration, oAuth2LoginAuthenticationToken.getAccessToken(), oAuth2LoginAuthenticationToken.getRefreshToken());
        OAuth2AccessTokenResponse accessTokenResponse = this.refreshTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);
        OidcIdToken idToken = this.authService.createOidcToken(clientRegistration, accessTokenResponse.getAccessToken().getTokenValue());
        OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration, accessTokenResponse.getAccessToken(), idToken, accessTokenResponse.getAdditionalParameters()));
        Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
        OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(clientRegistration, oAuth2LoginAuthenticationToken.getAuthorizationExchange(), oidcUser, mappedAuthorities, accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken());
        authenticationResult.setDetails(oAuth2LoginAuthenticationToken.getDetails());
        OAuth2AuthorizedClient updatedAuthorizedClient = new OAuth2AuthorizedClient(clientRegistration, oAuth2LoginAuthenticationToken.getName(), accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken());
        this.oauth2ClientService.saveAuthorizedClient(updatedAuthorizedClient, authenticationResult);
        attribute.setAuthentication(authenticationResult);
        session.setAttribute("SPRING_SECURITY_CONTEXT", attribute);
    }


}
