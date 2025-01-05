package cu.entalla.filter;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.config.CustomAuthorizationRequestResolver;
import cu.entalla.config.Wso2Config;
import cu.entalla.controller.SlingshotLoginController;
import cu.entalla.security.SecurityUtils;
import cu.entalla.service.ServiceLocator;
import cu.entalla.udi.AlfrescoIntegration;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.site.ClusterAwarePathStoreObjectPersister;
import org.alfresco.web.site.ClusterAwareRequestContextFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.*;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.persister.PersisterService;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ServletLinkBuilderFactory;
import org.springframework.extensions.surf.support.ServletRequestContextFactory;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.LocalWebScriptRuntimeContainer;
import org.springframework.extensions.webscripts.connector.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Wso2ShareAuthenticationFilter implements Filter {
    private static final Log logger = LogFactory.getLog(Wso2ShareAuthenticationFilter.class);
    private ApplicationContext context;
    private ConnectorService connectorService;
    private SlingshotLoginController loginController;
    private boolean enabled = false;
    public static final String ALFRESCO_ENDPOINT_ID = "alfresco";
    public static final String ALFRESCO_API_ENDPOINT_ID = "alfresco-api";
    public static final String SHARE_PAGE = "/share/page";
    public static final String SHARE_AIMS_LOGOUT = "/share/page/aims/logout";
    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
    private ClientRegistrationRepository clientRegistrationRepository;
    private OAuth2AuthorizedClientService oauth2ClientService;
    private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
    private RequestCache requestCache;
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
    private String redirectPage="/alfresco";

    public Wso2ShareAuthenticationFilter() {
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        if (logger.isInfoEnabled()) {
            logger.info("Initializing the Wso2ShareAuthenticationFilter filter.");
        }
        this.context = WebApplicationContextUtils.getRequiredWebApplicationContext(filterConfig.getServletContext());
        try {
            SpringContextHolder.registry(redirectPage,this.context);
            SpringContextHolder.setApplicationContext(redirectPage,this.context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Wso2Config config = (Wso2Config)this.context.getBean("wso2.config");
        this.enabled = config.isEnabled();
        if (this.enabled) {
            this.clientId = config.getResource();
            this.clientRegistrationRepository = (ClientRegistrationRepository)this.context.getBean(ClientRegistrationRepository.class);
            this.oauth2ClientService = (OAuth2AuthorizedClientService)this.context.getBean(OAuth2AuthorizedClientService.class);
            this.requestCache = new HttpSessionRequestCache();
            this.authorizationRequestResolver = new CustomAuthorizationRequestResolver(this.clientRegistrationRepository, "/oauth2/authorization");
            this.authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
            this.throwableAnalyzer = new SecurityUtils.DefaultThrowableAnalyzer();
        }
        this.connectorService = (ConnectorService)this.context.getBean("connector.service");
        this.loginController = (SlingshotLoginController)this.context.getBean("loginController");
        if (logger.isInfoEnabled()) {
            logger.info("Wso2 filter initialized.");
        }

    }

    public void doFilter(ServletRequest sreq, ServletResponse sres, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)sreq;
        HttpServletResponse response = (HttpServletResponse)sres;
        HttpSession session = request.getSession();
        boolean isAuthenticated = false;
        if (null != session && this.enabled) {
            SecurityContext attribute = (SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT");
            if (null != attribute) {
                isAuthenticated = attribute.getAuthentication().isAuthenticated();
                if (isAuthenticated) {
                    try {
                        this.refreshToken(attribute, session);
                    } catch (Exception var16) {
                        logger.error("Resulted in Error while doing refresh token " + var16.getMessage());
                        session.invalidate();
                        if (!request.getRequestURI().contains("/share/page/aims/logout")) {
                            isAuthenticated = false;
                        }
                    }
                }
            }
        }

        if (!isAuthenticated && this.enabled) {
            if (this.matchesAuthorizationResponse(request)) {
                this.processAuthorizationResponse(request, response, session);
            } else {
                try {
                    this.requestCache.saveRequest(request, response);
                    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request, this.clientId);
                    if (authorizationRequest != null) {
                        this.sendRedirectForAuthorization(request, response, authorizationRequest);
                        return;
                    }
                } catch (Exception var15) {
                    this.unsuccessfulRedirectForAuthorization(response);
                    return;
                }

                try {
                    chain.doFilter(request, response);
                } catch (IOException var13) {
                    throw var13;
                } catch (Exception var14) {
                    Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(var14);
                    ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException)this.throwableAnalyzer.getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
                    if (authzEx == null) {
                        if (var14 instanceof ServletException) {
                            throw (ServletException)var14;
                        }

                        if (var14 instanceof RuntimeException) {
                            throw (RuntimeException)var14;
                        }

                        throw new RuntimeException(var14);
                    }

                    try {
                        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request, authzEx.getClientRegistrationId());
                        if (authorizationRequest == null) {
                            throw authzEx;
                        }

                        this.sendRedirectForAuthorization(request, response, authorizationRequest);
                        this.requestCache.saveRequest(request, response);
                    } catch (Exception var12) {
                        this.unsuccessfulRedirectForAuthorization(response);
                    }
                }
            }
        } else {
            chain.doFilter(sreq, sres);
        }

    }

    private void onSuccess(HttpServletRequest request, HttpServletResponse response, HttpSession session, OAuth2LoginAuthenticationToken authenticationResult) {
        if (logger.isInfoEnabled()) {
            logger.info("Completing the WSO2 authentication.");
        }

        String username = (String)authenticationResult.getPrincipal().getAttribute("username");
        String accessToken = authenticationResult.getAccessToken().getTokenValue();
        synchronized(this) {
            try {
                this.initRequestContext(request, response,session);
                String alfTicket = this.getAlfTicket(session, username, accessToken);
                if (alfTicket != null) {
                    session.setAttribute("_alf_USER_ID", username);
                    session.setAttribute("X-Alfresco-Remote-User", username);
                    session.setAttribute("_alfExternalAuthAIMS", true);
                    session.setAttribute("_alfExternalAuthWSO2", true);
                    Connector connector = this.connectorService.getConnector("alfresco", username, session);
                    connector.getConnectorSession().setParameter("alfTicket", alfTicket);
                    CredentialVault vault = FrameworkUtil.getCredentialVault(session, username);
                    Credentials credentials = vault.newCredentials("alfresco");
                    credentials.setProperty("cleartextUsername", username);
                    vault.store(credentials);
                    this.loginController.beforeSuccess(request, response);
                    this.initUser(request);
                } else {
                    logger.error("Could not get an alfTicket from Repository.");
                }
            } catch (Exception var13) {
                throw new AlfrescoRuntimeException("Failed to complete WSO2 authentication process.", var13);
            }

        }
    }

    private AlfrescoIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response,HttpSession session) throws RequestContextException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        ApplicationContext shareContext=SpringContextHolder.getApplicationContext("/share");
        if (context == null && shareContext!=null) {
            //Object bean =SpringContextHolder.getBean(this.context,"webframework.factory.requestcontext.servlet");
            // ServletRequestContextFactory factory =bean!=null ? (ServletRequestContextFactory)bean:new ServletRequestContextFactory();

            Map<String, ConfigService> beansOfType = shareContext.getBeansOfType(ConfigService.class);
            logger.info("getBeansOfType ConfigService= "+beansOfType.size());
            ConfigService configService = beansOfType.get("web.config");

            logger.info("ClusterAwarePathStoreObjectPersister created... ");
            ClusterAwarePathStoreObjectPersister persister=new ClusterAwarePathStoreObjectPersister();
            String instanceName="softwarentalla-hazelcast-instance";
            persister.setHazelcastTopicName(instanceName);
            // Nombre del archivo en la ruta del classpath
            String configFileName = "alfresco/extension/hazelcastConfig.xml";
            // Cargar configuración desde el classpath
            Config config = new ClasspathXmlConfig(configFileName);
            config.setInstanceName(instanceName);

            AutowireService autowireService = new AutowireService();
            PersisterService persisterService = new PersisterService();
            persisterService.setPersisters(Arrays.asList(persister));
            persisterService.setAutowireService(autowireService);


            logger.info("Hazelcast config created... ");
            // Crear instancia de Hazelcast con la configuración cargada
            HazelcastInstance hazelcastInstance = Hazelcast.getOrCreateHazelcastInstance(config);
            logger.info("HazelcastInstance config created... ");
            persister.setHazelcastInstance(hazelcastInstance);
            ClusterAwareRequestContextFactory clusterAwareRequestContextFactory = new ClusterAwareRequestContextFactory();
            logger.info("ClusterAwareRequestContextFactory config created... ");
            clusterAwareRequestContextFactory.setClusterObjectPersister(persister);

            ConnectorService connectorService = new ConnectorService();
            connectorService.setApplicationContext(shareContext);
            connectorService.setConfigService(configService);

            ServletRequestContextFactory factory=(ServletRequestContextFactory)clusterAwareRequestContextFactory;
            factory.setApplicationContext(shareContext);
            ServletLinkBuilderFactory servletLinkBuilderFactory = new ServletLinkBuilderFactory();
            servletLinkBuilderFactory.setObjectUri("/page");
            servletLinkBuilderFactory.setPageTypeUri("/page");
            servletLinkBuilderFactory.setPageUri("/page");
            servletLinkBuilderFactory.setApplicationContext(shareContext);


            WebFrameworkServiceRegistry webFrameworkServiceRegistry = new WebFrameworkServiceRegistry();
            webFrameworkServiceRegistry.setConfigService(configService);
            webFrameworkServiceRegistry.setConnectorService(connectorService);
            webFrameworkServiceRegistry.setPersisterService(persisterService);

            servletLinkBuilderFactory.setServiceRegistry(webFrameworkServiceRegistry);
            FrameworkBean frameworkBean = new FrameworkBean();
            frameworkBean.setConnectorService(connectorService);
            RemoteConfigElement remoteConfigElement = new RemoteConfigElement();
            frameworkBean.setRemoteConfig(remoteConfigElement);
            LocalWebScriptRuntimeContainer localWebScriptRuntimeContainer = new LocalWebScriptRuntimeContainer();
            localWebScriptRuntimeContainer.setApplicationContext(shareContext);
            localWebScriptRuntimeContainer.bindRequestContext(context);
            localWebScriptRuntimeContainer.setConfigService(configService);

            frameworkBean.setWebFrameworkContainer(localWebScriptRuntimeContainer);

            servletLinkBuilderFactory.setFrameworkUtils(frameworkBean);

            factory.setLinkBuilderFactory(servletLinkBuilderFactory);
            factory.setConfigService(configService);
            context = factory.newInstance(new ServletWebRequest(request));
            request.setAttribute("requestContext", context);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        ServletUtil.setRequest(request);
        AlfrescoIntegration alfrescoIntegration = ServiceLocator.getAlfrescoIntegration();
        alfrescoIntegration.setRequest(request);
        alfrescoIntegration.setResponse(response);
        alfrescoIntegration.setSession(session);
        alfrescoIntegration.setApplicationContext(shareContext);
        ServiceLocator.registerAlfrescoIntegration(alfrescoIntegration);
        return alfrescoIntegration;
    }

    private void initUser(HttpServletRequest request) throws UserFactoryException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (context != null && context.getUser() == null) {
            String userEndpointId = (String)context.getAttribute("alfUserEndpoint");
            UserFactory userFactory = context.getServiceRegistry().getUserFactory();
            User user = userFactory.initialiseUser(context, request, userEndpointId);
            context.setUser(user);
        }

    }

    private String getAlfTicket(HttpSession session, String username, String accessToken) throws ConnectorServiceException {
        if (logger.isInfoEnabled()) {
            logger.info("Retrieving the Alfresco Ticket from Repository.");
        }

        String alfTicket = null;
        Connector connector = this.connectorService.getConnector("alfresco-api", username, session);
        ConnectorContext c = new ConnectorContext(HttpMethod.GET, (Map)null, Collections.singletonMap("Authorization", "Bearer " + accessToken));
        c.setContentType("application/json");
        Response r = connector.call("/-default-/public/authentication/versions/1/tickets/-me-?noCache=" + UUID.randomUUID().toString(), c);
        if (200 != r.getStatus().getCode()) {
            if (logger.isErrorEnabled()) {
                logger.error("Failed to retrieve Alfresco Ticket from Repository.");
            }
        } else {
            JSONObject json = new JSONObject(r.getText());
            try {
                alfTicket = json.getJSONObject("entry").getString("id");
            } catch (JSONException var10) {
                if (logger.isErrorEnabled()) {
                    logger.error("Failed to parse Alfresco Ticket from Repository response.");
                }
            }
        }

        return alfTicket;
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
                Set<Map.Entry<String, List<String>>> requestUriParameters = new LinkedHashSet(requestUri.getQueryParams().entrySet());
                Set<Map.Entry<String, List<String>>> redirectUriParameters = new LinkedHashSet(redirectUri.getQueryParams().entrySet());
                requestUriParameters.retainAll(redirectUriParameters);
                return Objects.equals(requestUri.getScheme(), redirectUri.getScheme()) && Objects.equals(requestUri.getUserInfo(), redirectUri.getUserInfo()) && Objects.equals(requestUri.getHost(), redirectUri.getHost()) && Objects.equals(requestUri.getPort(), redirectUri.getPort()) && Objects.equals(requestUri.getPath(), redirectUri.getPath()) && Objects.equals(requestUriParameters.toString(), redirectUriParameters.toString());
            }
        }
    }

    private synchronized void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException {
        OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
        MultiValueMap<String, String> params = SecurityUtils.toMultiMap(request.getParameterMap());
        String redirectUri = UrlUtils.buildFullRequestUrl(request);
        OAuth2AuthorizationResponse authorizationResponse = SecurityUtils.convert(params, redirectUri);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(this.clientId);
        OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
        authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

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
            this.onSuccess(request, response, session, authenticationResult);
        }

        if (savedRequest != null) {
            redirectUrl = savedRequest.getRedirectUrl();
            this.requestCache.removeRequest(request, response);
        }

        this.redirectStrategy.sendRedirect(request, response, redirectUrl);
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
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

    private synchronized void refreshToken(SecurityContext attribute, HttpSession session) {
        OAuth2LoginAuthenticationToken oAuth2LoginAuthenticationToken = (OAuth2LoginAuthenticationToken)attribute.getAuthentication();
        ClientRegistration clientRegistration = oAuth2LoginAuthenticationToken.getClientRegistration();
        OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(clientRegistration, oAuth2LoginAuthenticationToken.getAccessToken(), oAuth2LoginAuthenticationToken.getRefreshToken());
        OAuth2AccessTokenResponse accessTokenResponse = this.refreshTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);
        OidcIdToken idToken = this.createOidcToken(clientRegistration, accessTokenResponse);
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