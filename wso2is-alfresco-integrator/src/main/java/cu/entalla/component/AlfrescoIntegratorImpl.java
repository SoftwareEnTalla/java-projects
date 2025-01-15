package cu.entalla.component;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.LifecycleEvent;
import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.controller.SlingshotLoginController;
import cu.entalla.security.authentication.WSO2AuthenticationServiceImpl;
import cu.entalla.service.AuthenticationService;
import cu.entalla.service.ServiceLocator;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.udi.ClientServiceIntegration;
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
import org.springframework.context.annotation.Primary;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.*;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.persister.PersisterService;
import org.springframework.extensions.surf.support.ServletLinkBuilderFactory;
import org.springframework.extensions.surf.support.ServletRequestContextFactory;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.LocalWebScriptRuntimeContainer;
import org.springframework.extensions.webscripts.connector.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;


@Component
@Primary
public class AlfrescoIntegratorImpl implements ClientServiceIntegration {

    private static final Log logger = LogFactory.getLog(AlfrescoIntegratorImpl.class);
    private ConnectorService connectorService;

    private SlingshotLoginController loginController;
    private jakarta.servlet.http.HttpSession session;

    private HttpServletRequest request;
    private HttpServletResponse response;

    private ApplicationContext context;

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();

    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();

    private org.springframework.security.core.Authentication autentication;

    private final Wso2SecurityConfig wso2SecConfig=Wso2SecurityConfig.create();
    private final GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> {
        return authorities;
    };
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcUserService();

    public AlfrescoIntegratorImpl(jakarta.servlet.http.HttpSession session, ConnectorService connectorService){
        this.connectorService=connectorService;
        this.session=session;
        ServiceLocator.registerIntegrator(this);
       // inicialize();
    }
    public AlfrescoIntegratorImpl(jakarta.servlet.http.HttpServletRequest request, ConnectorService connectorService){
        this.connectorService=connectorService;
        this.request=request;
        this.session=request.getSession();
        ServiceLocator.registerIntegrator(this);
        //inicialize();
    }
    public AlfrescoIntegratorImpl(jakarta.servlet.http.HttpSession session){
        this.session=session;
        ServiceLocator.registerIntegrator(this);
        //this.inicialize();
    }
    public AlfrescoIntegratorImpl(){
        logger.info(":::::::::::::::::::::::: Se crea instancia de AlfrescoIntegratorImpl ::::::::::::::::::::::::");
        //this.inicialize();
        ServiceLocator.registerIntegrator(this);
    }


    public  ClientServiceIntegration inicialize(){
        logger.info("Ejecutando inicialize en AlfrescoIntegratorImpl.");
        this.loginController=new SlingshotLoginController();
        logger.info("Instancia de SlingshotLoginController creada.");
        context = SpringContextHolder.getApplicationContext("/share");
        logger.info("Contexto existe:"+(context!=null));
        logger.info("ConnectorService existe:"+(getConnectorService()!=null));
       if(this.getConnectorService()!=null && context!=null)
            this.connectorService.setApplicationContext(context);

        logger.info(":::::::::::::::::::::::: Se registra instancia de AlfrescoIntegratorImpl ::::::::::::::::::::::::");
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public ClientServiceIntegration  setSession(jakarta.servlet.http.HttpSession session){
        this.session=session;
        return this;
    }
    @Override
    public ClientServiceIntegration  setConnectorService(ConnectorService connectorService){
        this.connectorService=connectorService;
        if(this.connectorService!=null && context!=null)
            this.connectorService.setApplicationContext(context);
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public jakarta.servlet.http.HttpSession  getSession(){
        return this.session;
    }

    @Override
    public ClientServiceIntegration setRequest(HttpServletRequest request) {
        this.request=request;
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public HttpServletRequest getRequest() {
        return request;
    }

    @Override
    public  ClientServiceIntegration  setResponse(HttpServletResponse response) {
        this.response=response;
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public HttpServletResponse getResponse() {
        return response;
    }

    @Override
    public ConnectorService  getConnectorService(){
        if(this.connectorService==null && context!=null){
            this.connectorService=(ConnectorService)context.getBean("connector.service");
        }
        ServiceLocator.registerIntegrator(this);
        return this.connectorService;
    }
    @Override
    public ConnectorService  getConnectorService(ApplicationContext context){
        if(this.connectorService==null && context!=null){
            this.connectorService=(ConnectorService)context.getBean("connector.service");
        }
        ServiceLocator.registerIntegrator(this);
        return this.connectorService;
    }
    @Override
    public ConnectorService  getConnectorService(ApplicationContext context,String beanId){
        if(this.connectorService==null && context!=null){
            this.connectorService=(ConnectorService)context.getBean(beanId);
        }
        ServiceLocator.registerIntegrator(this);
        return this.connectorService;
    }
    @Override
    public String getTicket(String accessToken) {
        String alfHost="ses-cms.entalla.cu";
        String alfContext="alfresco";
        String shareContext="share";
        String alfTicket=null;
        try {
            inicialize();
            Wso2SecurityConfig wso2Config=Wso2SecurityConfig.create().loadProperties();
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2Config.getGlobalPropertyFile());
            AuthenticationService authService=new AuthenticationService(client);
            AuthenticationStore.getInstance().setWso2SecurityConfig(wso2Config);
            wso2Config=AuthenticationStore.getInstance().getWso2SecurityConfig();
            alfHost=wso2Config.getPropertyByKey("alfresco.host",alfHost);
            alfContext=wso2Config.getPropertyByKey("alfresco.context",alfContext);
            shareContext=wso2Config.getPropertyByKey("share.context",shareContext);
            WSO2AuthenticationServiceImpl wso2AuthService=new WSO2AuthenticationServiceImpl();
            alfTicket=wso2AuthService.getTicket(accessToken,true);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return alfTicket;
    }

    @Override
    public String getTicket(String sessionId, String username, String accessToken) {
        // Lógica para generar el ticket de Alfresco
        if (logger.isInfoEnabled()) {
            logger.info("Retrieving the Alfresco Ticket from Repository.");
        }
        logger.info("Intentando capturar el contexto de /share .");
        ApplicationContext context=SpringContextHolder.getApplicationContext("/share");
        inicialize();
        String alfTicket = null;
        ConnectorService service=null;
        try{

            if(context!=null){
                String connectorServiceId = "connector.service";//"custom-conector-service";
                service = this.getConnectorService(context, connectorServiceId);
                if(service!=null) {

                    logger.info(":::::::::::::::::::::::::::::::::::::::::::  Class Of ConnectorService===> " + service.getClass());
                    logger.info(":::::::::::::::::::::::::::::::::::::::::::  Class Of ConfigService===> " + service.getConfigService().getClass());
                    service.setApplicationContext(context);
                    Map<String, ConfigService> beansOfType = context.getBeansOfType(ConfigService.class);
                    logger.info("getBeansOfType ConfigService= " + beansOfType.size());
                    ConfigService configService = beansOfType.get("web.config");
                    this.getConnectorService().setConfigService(configService);
                    Connector connector = service.getConnector("alfresco-api", username, session);
                    logger.info("Getting connector from alfresco-api.");
                    Map<String, String> headers = Collections.singletonMap("Authorization", "Bearer " + accessToken);
                    headers.put("X-Alfresco-Remote-User",username);
                    ConnectorContext c = new ConnectorContext(HttpMethod.GET, (Map<String, String>) null,headers );
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
                }
                else {
                    logger.warn("ConnectorService no encontrado. Usando HttpClient para realizar la petición.");
                    Wso2AuthenticatorClient client = Wso2AuthenticatorClient.getInstance();
                    HttpClient httpClient = client.getHttpClient();
                    String url = "/-default-/public/authentication/versions/1/tickets/-me-?noCache=" + UUID.randomUUID().toString();
                    logger.warn("Call to Uri:"+url);
                    // Configurar los encabezados
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(url))
                            .header("Authorization", "Bearer " + accessToken)
                            .header("X-Alfresco-Remote-User", username)
                            .header("Content-Type", "application/json")
                            .GET()
                            .build();

                    try {
                        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                        if (response.statusCode() == 200) {
                            logger.info("GET request successful.");
                            String responseBody = response.body();
                            JSONObject json = new JSONObject(responseBody);

                            try {
                                alfTicket = json.getJSONObject("entry").getString("id");
                                logger.info("Alfresco Ticket retrieved successfully: " + alfTicket);
                            } catch (JSONException e) {
                                logger.error("Failed to parse Alfresco Ticket from Repository response.", e);
                            }
                        } else {
                            logger.error("Failed to retrieve Alfresco Ticket. Status code: " + response.statusCode() + ", Response: " + response.body());
                        }
                    } catch (IOException | InterruptedException e) {
                        logger.error("Exception while sending GET request: ", e);
                    }
                }
            }
            else {
                logger.info("El contexto para /share es null.");
            }

        }catch (ConnectorServiceException cse){
            logger.error(cse.getMessage());
            alfTicket=getTicket(accessToken);
        }
        ServiceLocator.registerIntegrator(this);
        return alfTicket;
    }

    @Override
    public ApplicationContext getApplicationContext() {
        this.context=this.context!=null?this.context:(this.context=SpringContextHolder.getApplicationContext("/share"));
        ServiceLocator.registerIntegrator(this);
        return this.context;
    }

    @Override
    public ClientServiceIntegration setApplicationContext(ApplicationContext context) {
            this.context=context;
            ServiceLocator.registerIntegrator(this);
            return this;
    }


    @Override
    public ClientServiceIntegration configureSession(jakarta.servlet.http.HttpSession session, String username, String alfTicket) {

        synchronized(this) {
            try {

                if (alfTicket != null) {
                    // Configura la sesión con el ticket
                    session.setAttribute("_alf_USER_ID", username);
                    session.setAttribute("alfTicket", alfTicket);
                    session.setAttribute("X-Alfresco-Remote-User", username);
                    session.setAttribute("Alfresco-Ticket", alfTicket);
                    session.setAttribute("_alfExternalAuthAIMS", true);
                    session.setAttribute("_alfExternalAuthWSO2", true);

                    Connector connector = this.connectorService.getConnector("alfresco", username, session);
                    connector.getConnectorSession().setParameter("alfTicket", alfTicket);
                    CredentialVault vault = FrameworkUtil.getCredentialVault(session, username);
                    Credentials credentials = vault.newCredentials("alfresco");
                    credentials.setProperty("cleartextUsername", username);
                    vault.store(credentials);
                    if(this.loginController==null)
                        this.loginController=new SlingshotLoginController();
                    if(request!=null && response!=null){
                        this.loginController.beforeSuccess(request, response);
                        this.initUser(request);
                    }

                } else {
                    logger.error("Could not get an alfTicket from Repository.");
                }
            } catch (Exception var13) {
                throw new AlfrescoRuntimeException("Failed to complete AIMS authentication process.", var13);
            }

        }
        ServiceLocator.registerIntegrator(this);
        return this;
    }
    @Override
    public ClientServiceIntegration initUser(HttpServletRequest request) throws UserFactoryException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (request!=null && context != null && context.getUser() == null) {
            this.request=request;
            this.session=request.getSession();
            String userEndpointId = (String)context.getAttribute("alfUserEndpoint");
            UserFactory userFactory = context.getServiceRegistry().getUserFactory();
            org.springframework.extensions.webscripts.connector.User user = userFactory.initialiseUser(context, request, userEndpointId);
            context.setUser(user);
        }
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public ClientServiceIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response) throws RequestContextException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (context == null && this.context!=null) {
            //Object bean =SpringContextHolder.getBean(this.context,"webframework.factory.requestcontext.servlet");
            // ServletRequestContextFactory factory =bean!=null ? (ServletRequestContextFactory)bean:new ServletRequestContextFactory();

            Map<String, ConfigService> beansOfType = this.context.getBeansOfType(ConfigService.class);
            logger.info("getBeansOfType ConfigService= "+beansOfType.size());
            ConfigService configService = beansOfType.get("web.config");

            logger.info("ClusterAwarePathStoreObjectPersister created... ");
            ClusterAwarePathStoreObjectPersister persister=new ClusterAwarePathStoreObjectPersister();


            boolean loadHazelCast=wso2SecConfig.getPropertyByKey("hazelcast.instance.enabled","")=="true";
            if(loadHazelCast) {
                // Crear instancia de Hazelcast con la configuración cargada
                String instanceName = "softwarentalla-hazelcast-instance";
                persister.setHazelcastTopicName(instanceName);
                // Nombre del archivo en la ruta del classpath
                logger.info("...................Creando instancia de HazelCast en AlfrescoIntegratorImpl............");
                HazelcastInstance hazelcastInstance = SpringContextHolder.hazelcastClassPathInstance();
                hazelcastInstance.getLifecycleService().addLifecycleListener(event -> {
                    if (event.getState() == LifecycleEvent.LifecycleState.SHUTTING_DOWN) {
                        hazelcastInstance.shutdown();
                    }
                });
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("Apagando la JVM. Cerrando Hazelcast...");
                    hazelcastInstance.shutdown();
                }));
                logger.info("Hazelcast Config created::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: ");
                persister.setHazelcastInstance(hazelcastInstance);
            }

            AutowireService autowireService = new AutowireService();
            PersisterService persisterService = new PersisterService();
            persisterService.setPersisters(Arrays.asList(persister));
            persisterService.setAutowireService(autowireService);


            ClusterAwareRequestContextFactory clusterAwareRequestContextFactory = new ClusterAwareRequestContextFactory();
            logger.info("ClusterAwareRequestContextFactory created... ");
            clusterAwareRequestContextFactory.setClusterObjectPersister(persister);

            ConnectorService connectorService = new ConnectorService();
            connectorService.setApplicationContext(this.context);
            connectorService.setConfigService(configService);

            ServletRequestContextFactory factory=(ServletRequestContextFactory)clusterAwareRequestContextFactory;
            factory.setApplicationContext(this.context);
            ServletLinkBuilderFactory servletLinkBuilderFactory = new ServletLinkBuilderFactory();
            servletLinkBuilderFactory.setObjectUri("/page");
            servletLinkBuilderFactory.setPageTypeUri("/page");
            servletLinkBuilderFactory.setPageUri("/page");
            servletLinkBuilderFactory.setApplicationContext(this.context);
            logger.info("ServletRequestContextFactory created... ");

            WebFrameworkServiceRegistry webFrameworkServiceRegistry = new WebFrameworkServiceRegistry();
            webFrameworkServiceRegistry.setConfigService(configService);
            webFrameworkServiceRegistry.setConnectorService(connectorService);
            webFrameworkServiceRegistry.setPersisterService(persisterService);
            logger.info("WebFrameworkServiceRegistry created... ");
            servletLinkBuilderFactory.setServiceRegistry(webFrameworkServiceRegistry);
            FrameworkBean frameworkBean = new FrameworkBean();
            frameworkBean.setConnectorService(connectorService);
            RemoteConfigElement remoteConfigElement = new RemoteConfigElement();
            frameworkBean.setRemoteConfig(remoteConfigElement);
            LocalWebScriptRuntimeContainer localWebScriptRuntimeContainer = new LocalWebScriptRuntimeContainer();
            localWebScriptRuntimeContainer.setApplicationContext(this.context);
            localWebScriptRuntimeContainer.bindRequestContext(context);
            localWebScriptRuntimeContainer.setConfigService(configService);
            logger.info("LocalWebScriptRuntimeContainer created... ");
            frameworkBean.setWebFrameworkContainer(localWebScriptRuntimeContainer);

            servletLinkBuilderFactory.setFrameworkUtils(frameworkBean);

            factory.setLinkBuilderFactory(servletLinkBuilderFactory);
            factory.setConfigService(configService);
            context = factory.newInstance(new ServletWebRequest(request));
            logger.info("ServletWebRequest created... ");
            request.setAttribute("requestContext", context);
            logger.info("requestContext saved on HttpRequest instance... ");
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        ServletUtil.setRequest(request);
        logger.info("RequestContextHolder modified... ");
        ClientServiceIntegration integration = ServiceLocator.getIntegrator();
        integration.setRequest(request);
        integration.setResponse(response);
        integration.setSession(session);
        integration.setApplicationContext(SpringContextHolder.getApplicationContext("/share"));
        ServiceLocator.registerIntegrator(integration);
        logger.info("integration instance was registered... ");
        ServiceLocator.registerIntegrator(integration);
        return integration;
    }

    @Override
    public ClientServiceIntegration initRequestContext(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws RequestContextException {
        this.setSession(session);
        return initRequestContext(request,response);
    }
    public Authentication getAutentication(){
        return autentication;
    }

    @Override
    public ClientServiceIntegration setAutentication(Authentication autentication) {
        this.autentication=autentication;
        return this;
    }

    @Override
    public Authentication authenticate(Function<Object, Authentication> processor, Object obj) throws AuthenticationException {
        Authentication authentication = processor.apply(obj);
        autentication=authenticate(authentication);
        ServiceLocator.registerIntegrator(this);
        return authentication;
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken)authentication;
        if (!authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
            logger.info(":::::::::::::: Authentication need openid scope...");
            return null;
        } else {
            OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest();
            OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationResponse();
            if (authorizationResponse.statusError()) {
                logger.error(":::::::::::::: Authentication Error:"+authorizationResponse.statusError());
                throw new OAuth2AuthenticationException(authorizationResponse.getError(), authorizationResponse.getError().toString());
            } else if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
                OAuth2Error oauth2Error = new OAuth2Error("invalid_state_parameter");
                logger.error(":::::::::::::: Authentication Error:"+oauth2Error.getErrorCode());
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            } else {
                OAuth2AccessTokenResponse accessTokenResponse;
                try {
                    accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange()));
                    logger.info(":::::::::::::: Authentication valid accessTokenResponse :"+(accessTokenResponse!=null));
                } catch (OAuth2AuthorizationException var14) {
                    OAuth2Error oauth2Error = var14.getError();
                    logger.info(":::::::::::::: Authentication Error:"+oauth2Error.getErrorCode());
                    throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                }

                ClientRegistration clientRegistration = authorizationCodeAuthentication.getClientRegistration();
                Map<String, Object> additionalParameters = accessTokenResponse.getAdditionalParameters();
                if (!additionalParameters.containsKey("id_token")) {
                    OAuth2Error invalidIdTokenError = new OAuth2Error("invalid_id_token", "Missing (required) ID Token in Token Response for Client Registration: " + clientRegistration.getRegistrationId(), (String)null);
                    logger.info(":::::::::::::: Authentication Error:"+invalidIdTokenError.getErrorCode());
                    throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
                } else {
                    OidcIdToken idToken = this.createOidcToken(clientRegistration, accessTokenResponse);
                    String requestNonce = (String)authorizationRequest.getAttribute("nonce");
                    if (requestNonce != null) {
                        String nonceHash;
                        OAuth2Error oauth2Error;
                        try {
                            nonceHash = createHash(requestNonce);
                            logger.info(":::::::::::::: Authentication nonce builder:"+nonceHash);
                        } catch (NoSuchAlgorithmException var13) {
                            oauth2Error = new OAuth2Error("invalid_nonce");
                            logger.info(":::::::::::::: Authentication Error:"+oauth2Error.getErrorCode());
                            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                        }

                        String nonceHashClaim = idToken.getNonce();
                        if (nonceHashClaim == null || !nonceHashClaim.equals(nonceHash)) {
                            oauth2Error = new OAuth2Error("invalid_nonce");
                            logger.info(":::::::::::::: Authentication Error:"+oauth2Error.getErrorCode());
                            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                        }
                    }
                    logger.info(":::::::::::::: Authentication oidcUser builder starting...");
                    OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration, accessTokenResponse.getAccessToken(), idToken, additionalParameters));
                    Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
                    OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oidcUser, mappedAuthorities, accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken());
                    authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
                    logger.info(":::::::::::::: Authentication oidcUser finish very well...");
                    autentication=authenticationResult;
                    ServiceLocator.registerIntegrator(this);
                    return authentication;
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
    @Override
    public ClientServiceIntegration configureSession(HttpServletRequest request, String usernameKey, String alfTicketKey) {
        if(request!=null) {
            this.request=request;
            this.session=request.getSession();
            Enumeration<String> attributeNames = request.getAttributeNames();
            // Convertir a un conjunto
            Set<String> attributesSet = Collections.list(attributeNames).stream().collect(Collectors.toSet());
            String userName = attributesSet.contains(usernameKey) ? request.getAttribute(usernameKey).toString() : null;
            String alfTicket = attributesSet.contains(alfTicketKey) ? request.getAttribute(alfTicketKey).toString() : null;
            if (userName != null && alfTicket != null)
                configureSession(request.getSession(), userName, alfTicket);
        }
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public ClientServiceIntegration configureSession(HttpServletRequest request, HttpServletResponse response, String userName, String alfTicket) {
        if(request!=null && response!=null){
            session=request.getSession();
            synchronized(this) {
                try {

                    if (alfTicket != null) {
                        // Configura la sesión con el ticket
                        session.setAttribute("_alf_USER_ID", userName);
                        session.setAttribute("alfTicket", alfTicket);
                        session.setAttribute("X-Alfresco-Remote-User", userName);
                        session.setAttribute("Alfresco-Ticket", alfTicket);
                        session.setAttribute("_alfExternalAuthAIMS", true);
                        session.setAttribute("_alfExternalAuthWSO2", true);

                        Connector connector = this.connectorService.getConnector("alfresco", userName, session);
                        connector.getConnectorSession().setParameter("alfTicket", alfTicket);
                        CredentialVault vault = FrameworkUtil.getCredentialVault(session, userName);
                        Credentials credentials = vault.newCredentials("alfresco");
                        credentials.setProperty("cleartextUsername", userName);
                        vault.store(credentials);
                        if(this.loginController==null)
                            this.loginController=new SlingshotLoginController();
                        if(request!=null && response!=null){
                            this.loginController.beforeSuccess(request, response);
                            this.initUser(request);
                        }

                    } else {
                        logger.error("Could not get an alfTicket from Repository.");
                    }
                } catch (Exception var13) {
                    throw new AlfrescoRuntimeException("Failed to complete AIMS authentication process.", var13);
                }

            }
        }
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public ClientServiceIntegration configureSession(HttpServletRequest request, HttpServletResponse response, HttpSession session, String userName, String alfTicket) {
        if(request!=null && response!=null){
            synchronized(this) {
                try {

                    if (alfTicket != null) {
                        // Configura la sesión con el ticket
                        session.setAttribute("_alf_USER_ID", userName);
                        session.setAttribute("alfTicket", alfTicket);
                        session.setAttribute("X-Alfresco-Remote-User", userName);
                        session.setAttribute("Alfresco-Ticket", alfTicket);
                        session.setAttribute("_alfExternalAuthAIMS", true);
                        session.setAttribute("_alfExternalAuthWSO2", true);

                        Connector connector = this.connectorService.getConnector("alfresco", userName, session);
                        connector.getConnectorSession().setParameter("alfTicket", alfTicket);
                        CredentialVault vault = FrameworkUtil.getCredentialVault(session, userName);
                        Credentials credentials = vault.newCredentials("alfresco");
                        credentials.setProperty("cleartextUsername", userName);
                        vault.store(credentials);
                        if(this.loginController==null)
                            this.loginController=new SlingshotLoginController();
                        if(request!=null && response!=null){
                            this.loginController.beforeSuccess(request, response);
                            this.initUser(request);
                        }

                    } else {
                        logger.error("Could not get an alfTicket from Repository.");
                    }
                } catch (Exception var13) {
                    throw new AlfrescoRuntimeException("Failed to complete AIMS authentication process.", var13);
                }

            }
        }
        ServiceLocator.registerIntegrator(this);
        return this;
    }

    @Override
    public ClientServiceIntegration getInstance() {
        ServiceLocator.registerIntegrator(this);
        return this;
    }

}
