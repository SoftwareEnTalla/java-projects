//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.security.authentication.WSO2AuthenticationServiceImpl;
import cu.entalla.service.AuthenticationService;
import cu.entalla.service.ServiceLocator;
import cu.entalla.udi.ClientServiceIntegration;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.site.servlet.config.AIMSConfig;
import org.alfresco.web.site.servlet.config.CustomAuthorizationRequestResolver;
import org.alfresco.web.site.servlet.config.SecurityUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ServletRequestContextFactory;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
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
import org.springframework.security.oauth2.core.*;
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
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class AIMSFilter implements Filter {
    private static final Log logger = LogFactory.getLog(AIMSFilter.class);
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
    private Wso2SecurityConfig wso2SecConfig =new Wso2SecurityConfig().loadProperties();


    AuthenticationService authService =new AuthenticationService();

    public AIMSFilter() {
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        if (logger.isInfoEnabled()) {
            logger.info("Initializing the AIMS filter.");
        }

        this.context = WebApplicationContextUtils.getRequiredWebApplicationContext(filterConfig.getServletContext());
        AIMSConfig config = (AIMSConfig)this.context.getBean("aims.config");
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
            logger.info("AIMS filter initialized.");
        }

    }

    public void doFilter(ServletRequest sreq, ServletResponse sres, FilterChain chain) throws IOException, ServletException {
        this.request= (HttpServletRequest) sreq;
        this.response= (HttpServletResponse) sres;
        HttpServletRequest request = (HttpServletRequest)sreq;
        HttpServletResponse response = (HttpServletResponse)sres;
        HttpSession session = request.getSession();
        ClientServiceIntegration integrator = ServiceLocator.getIntegrator();
        boolean initAuthenticationState=integrator!=null && integrator.getAutentication()!=null && integrator.getAutentication().isAuthenticated()||request.getSession().getAttribute("X-Access-Tocken")!=null;
        boolean isAuthenticated = initAuthenticationState;

        if(isAuthenticated)
        {
            SecurityContext secContext=new SecurityContextImpl();
            secContext.setAuthentication(integrator.getAutentication());
            session.setAttribute("SPRING_SECURITY_CONTEXT",secContext);
            logger.error("------------------------- Resulta que ya el usuario está autenticado con ClientServiceIntegration -----------------------");
            chain.doFilter(sreq, sres);
            return;
        }

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
            logger.info("Completing the AIMS authentication.");
        }

        String username = (String)authenticationResult.getPrincipal().getAttribute("preferred_username");
        String accessToken = authenticationResult.getAccessToken().getTokenValue();
        synchronized(this) {
            try {
                this.initRequestContext(request, response);
                String alfTicket = this.getAlfTicket(session, username, accessToken);
                if (alfTicket != null) {
                    session.setAttribute("_alf_USER_ID", username);
                    session.setAttribute("_alfExternalAuthAIMS", true);
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
                throw new AlfrescoRuntimeException("Failed to complete AIMS authentication process.", var13);
            }

        }
    }

    private void initRequestContext(HttpServletRequest request, HttpServletResponse response) throws RequestContextException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (context == null) {
            ServletRequestContextFactory factory = (ServletRequestContextFactory)this.context.getBean("webframework.factory.requestcontext.servlet");
            context = factory.newInstance(new ServletWebRequest(request));
            request.setAttribute("requestContext", context);
        }

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        ServletUtil.setRequest(request);
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
            var16.printStackTrace();
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
            this.onSuccess(request, response, session, authenticationResult);
        }

        if (savedRequest != null) {
            redirectUrl = savedRequest.getRedirectUrl();
            this.requestCache.removeRequest(request, response);
        }

        this.redirectStrategy.sendRedirect(request, response, redirectUrl);
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
                        OidcIdToken idToken = this.authService.getOidcIdToken();
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
            if(refreshToken==null){
                SecurityContext attribute = (SecurityContext)request.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
                refreshToken(attribute,request.getSession());
                refreshToken=request.getSession().getAttribute("refresh_token");
            }
            OAuth2RefreshToken oAuth2RefreshToken = new OAuth2RefreshToken(refreshToken != null ? refreshToken.toString() : null, Instant.now());
            ClientRegistration clientRegistration= this.clientRegistrationRepository.findByRegistrationId("wso2");
            OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration,oauth2AccessToken, idToken, additionalParameters));
            Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
            OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oidcUser, mappedAuthorities, oauth2AccessToken, oAuth2RefreshToken);
            authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
            return authenticationResult;
        }
    }
    Map<String, Object> additionalParameters = new HashMap<>();
    OAuth2AccessToken oauth2AccessToken;
    HttpServletRequest request;
    HttpServletResponse response;
    public static void main(String[] args){
        AIMSFilter filter=new AIMSFilter();
        Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create().loadProperties();
        String accessToken="eyJ4NXQiOiJZVEpsTTJabE56RXlZbU5rTXpsbE1ERmtNbVE0WWpRek9EVTBOVFZpWm1NeU1qUXhaREV3WWpZeU5qazFNalpqT0dSa01XTmxPVEEwWkdRellUQTNOdyIsImtpZCI6IllUSmxNMlpsTnpFeVltTmtNemxsTURGa01tUTRZalF6T0RVME5UVmlabU15TWpReFpERXdZall5TmprMU1qWmpPR1JrTVdObE9UQTBaR1F6WVRBM053X1JTMjU2IiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI4MGYwMGI1Yy0wYmEyLTQ1NzItOTU3YS1hOTY3ODI5OTlmMDYiLCJhdXQiOiJBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoic3NvLXNlc3Npb24iLCJpc3MiOiJodHRwczpcL1wvc2VzLWlkcC5lbnRhbGxhLmN1Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJnaXZlbl9uYW1lIjoiUGVyc3kiLCJjbGllbnRfaWQiOiJGQTZVQW9iZDJFeFkyaHVhZzVDSUJhendHWjBhIiwiYXVkIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm5iZiI6MTczNjcwODE2MSwiYXpwIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm9yZ19pZCI6IjEwMDg0YThkLTExM2YtNDIxMS1hMGQ1LWVmZTM2YjA4MjIxMSIsInNjb3BlIjoiZW1haWwgb3BlbmlkIHBob25lIHByb2ZpbGUiLCJwaG9uZV9udW1iZXIiOiIrNTMgNTMzNjQ2NTQiLCJleHAiOjE3MzY3MTE3NjEsIm9yZ19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MzY3MDgxNjEsImZhbWlseV9uYW1lIjoiTW9yZWxsIEd1ZXJyYSIsImJpbmRpbmdfcmVmIjoiNTExZTg2YTZmMmNiNGMxMWM5MzY2MTM5ZTM4ZWY0NzkiLCJqdGkiOiI4MzAyZWExYi00NTUwLTQ5NmEtOWUwZi02YjVmZWE1M2E1NjkiLCJlbWFpbCI6InBtb3JlbGxAeGV0aWQuY3UiLCJ1c2VybmFtZSI6ImFkbWluIn0.Ap-QMlaULyuY9Nl7jQ8NUuKPinV_Jg5Tw0_ce8nRBf-BeK3Le4PqShsg7_40ATW1EzKIt7xZnHPRCdtiWHF69l95UtQXBoXukOwsRzkHL8ctpNQWQg6jGZZcUx1cYUW9TYxdl6b7lVx4mcUbQ0BCh88G872LdjPolPQ7ECGaPsyF9DmcC7ZfMkX5QT-1CZZjvxXB-BOMVpMWkEOWDxEYjwoW_tZHUoRTS2cHUJUTdmn8pR5xstaMFw6jeBqFFy8iyAz9DGHjJazMIH9r1zXag49cV8ZobCt5Z_61fHXQyVlfPkKxwivVlUA-TGFxlQiYusbvAapBvBVQ-UCWqH2uzA";
        String idToken="eyJraWQiOiJOVEprTnpRM016Z3dZbVEzTW1FMk1EYzNPV0l6WW1OaU4yVTRZVFZoTmpVME5qSTFNMlU1WlRoak0yRTFPV013Wm1aaVpHWTBNR0ZoTnpFNE9EY3lNQSIsImN0eSI6IkpXVCIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUCJ9.QVzfYF6gEvhbMJss3wB8GB-7uxIDsKtQ9Nsy5pH5_4EU5DY9FTafOvtqKs88k8_kNJLxghM6GuAjMQZ2DIg_Nbc5V8UqF9m0Oh1-mffArUDxpdGcpFTODZDnOvLq9UkbWRLuo67VhVpjAl2hzHQj_mvDaLoD8QWN_tnMcWP9mSKo4aPw_s4vbprehB_Vd7OAl7rve8J_qr7WWsZVcHEnC0NyUbondbYpjGs2_yP7B4IocN4pRhHGqreDyQvXcrtBd7jK57VYrBs0Oz2pi2Nb35OOQqPvqd5gv39txbbOdremgn7WVFTgYFdCBnoKrKPVPB5m9m7a_SA0ibbsi_otKw.N4YrRErZCDpjgJTB.2kkwOd5ZFGk5EeSguTC-65LxkgzWeeq0Cl0YRbe4HKE8URAuUfmjpyQeMkHnLR8rCsecYIMqPsk8ja9j3qfk-HZD0WRPVebE6P-mLndhaCBgPXbGZjc3OioA1ejNH9WSrBl49WkJTLnlUpPdG_Otuc02uZtvv033y20fkJBVPWniqIwmPDg8Nk3WpbQNo2r5FoyI4E1XNhEvLUUzAKJORBL9S-EPOdLnb7ekNtMVzgs7EyUxuaGYvdy7vCDp0hyH-Vc16SdFKVfAIQDY0cTTzRubv818MM0_ss2KzXQgZk9-DIUvmIRa6PG6SmhZfKcFyoWKodApFNmw8IB2h_mSab7K49Yc171ebqiUMD4drycXqD27NbhNnX8b9JusIy_24GZ7OjKQv-uHKDjA8UkNuMe49sA6HmzW-RO_IUwVFSQLvR_MFTQZsHKOSVYt_FaPAyqDSlyPG3XwnvNtI3MfJO4ohJ02rErLuciZ3zHXpjBZ9B3r3K2Z7ZVN665c-c2df7arjd2uwfZ-ZIHWOzany-_Pw_demiJaFlIxHFhuLSXTQllKFHUK_XJ440D26RorKaZbMQnryBNowx1s0kxl9JYCrORw2Z4HzrDUJQw0fK6l0jjcWoLa7iXmV4tKDFWjjL4WYDtV2B2vPst6j6bqts6DIb9T0tkjLkIoeX07M48RGEz0MNeYWp5POadP4LzZs8iEUbwfX6uGunA582UavtpWhz201ILrG_wl3SHHdQ_PuA7e1UmrnC0GzUpKUB5hqLrMgXoEmBFUUEGeNwWcRSSLDTPghVfj5gjCTlP0LE7dV240ng8KYtztrFonRUjCdjo2NJoXQqYLUl50eRxdE-eCStzCFr0xzubUI3G0AjUOLtDFKSRzx35ORRbTzbwrJMFpzo_l8OFsDnLBOEkGuhOn5CWdsCzY0q8M4abhCgYhP-PNzI6BvxK6VIjQJA4_UgjS1tQJc8qEGmeePpHDX6wozQjxSCL4vgvA8LIB5HnCeBvfN1fXOujCdnXOxJh3lqZ-2AMIKgfJl7nCYzD_pnjlsKgQ914gJo8rSl2r0kW0zHqt25uphojgpRV2Tyoavyd2_FR69e7YWpLj-Idbz2MAKeARB0pd_5gSHNfkNi11kWAFej9I8VUMtyvgBB0-U6wQ21jrto8tew5KV82R6qniIx_kqNRWfZJhxQ2pF8VX4fl0gZpDGoDxnZmcvwsRbjTtfIKa7bXpCxz021I9HHaELXkXk7p3f-1o7VNDaBSfDqtDio-5ToZFLB9L0Nwk6Cb_UOoMidpmbRWfdBUaSnflZ0FskEDtNOK5xLoIkUv27YATvHjelBsWb9lUpzhQkzB0YX2hNk5OQ8b_k_nKDUIPBKhJQe-mS6JOCLLRzFiNamedY8DbNafvbwnflLSNJzD4R_TQBrZ_PhWTqh271H90bje_nNwoiuOl0eMtY71bPSEwuh4fmytkPOszxF6-xy6adeUrfdw55pStHxpgPZVhdQXMaQnMH-W1BuyA66owyytkV4dC7RLYcweSWnmkREAqHHqHWXVXUI33uVxJVwoGTwH33H7hvnloGZqyzJTiLjarsWzKnF7r445JLlGZN2_Qf-D01B3zivnS2lP71ARG5EmMH4u8VhJ9IOg2RWJE5m7ZXU7W5fhPCplHoEEzIg0V1Jx-J1ZSDrW6ey9LXRkHCN8TBzrv8djfQ0e8rfFsHHagMGpV-ozjYn8n_GtKpCR9yhGVw-64YLkRvdG59nblqd0sltezaK35wtchSPnOihWBLspBQJixQI5TP-2mfmliJqTAQ04gcmvOJEmv3jaqHjiNn4A_mBF1qVjBYdF9IxnPJgta8AdOtM12MhIHcxFEXk7v2SYAysC6Z2k6p5QewNAufVB2fdKonjETklA3lPuFTDiVwl9LKuii2Wca3ZsdjKobBJw-fKpCH8Iot5-oBLubREt3fqy9mQCQGJ_S9HG6N86A-W4EHbIoNBJMQ-7ivdVF97d4MgI7NZHAR7Gax-UgRFdstlrUBTdXHS2n_xKw_ZuquHb4z--DhkI3DQ.YaMTrZQRzzsFTp7kn7ZvBw";
        Set<String> scopes= Arrays.stream("email openid phone profile".split(" ")).collect(Collectors.toSet());
        Map<String,Object> parameters=new HashMap<>();
        parameters.put("id_token",idToken);
        parameters.put("refresh_token","3e95f1ea-c6e9-3f97-980b-d44432afd385");
        OAuth2AccessTokenResponse response=OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .scopes(scopes)
                .additionalParameters(parameters)
                .build();
        filter.createOidcToken(wso2SecurityConfig.clientRegistrationRepository().findByRegistrationId("wso2"),response );
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
