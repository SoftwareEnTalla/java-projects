package cu.entalla.filter;

import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.security.Principal;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.RealmCallback;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.jlan.server.auth.kerberos.KerberosDetails;
import org.alfresco.jlan.server.auth.ntlm.NTLM;
import org.alfresco.jlan.server.auth.ntlm.NTLMLogonDetails;
import org.alfresco.jlan.server.auth.ntlm.NTLMMessage;
import org.alfresco.jlan.server.auth.ntlm.Type1NTLMMessage;
import org.alfresco.jlan.server.auth.ntlm.Type2NTLMMessage;
import org.alfresco.jlan.server.auth.ntlm.Type3NTLMMessage;
import org.alfresco.jlan.server.auth.spnego.NegTokenInit;
import org.alfresco.jlan.server.auth.spnego.NegTokenTarg;
import org.alfresco.jlan.server.auth.spnego.OID;
import org.alfresco.jlan.server.auth.spnego.SPNEGO;
import org.alfresco.util.Pair;
import org.alfresco.util.log.NDC;
import org.alfresco.web.site.servlet.KerberosSessionSetupPrivilegedAction;
import org.alfresco.web.site.servlet.SlingshotLoginController;
import org.alfresco.web.site.servlet.config.AIMSConfig;
import org.alfresco.web.site.servlet.config.KerberosConfigElement;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.PlatformRuntimeException;
import org.springframework.extensions.surf.mvc.PageViewResolver;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.types.Page;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.servlet.DependencyInjectedFilter;
import org.springframework.web.util.WebUtils;

public class EnTallaSSOAuthenticationFilter implements DependencyInjectedFilter, CallbackHandler, ApplicationContextAware {
    private static Log logger = LogFactory.getLog(EnTallaSSOAuthenticationFilter.class);
    private static final String AUTH_NTLM = "NTLM";
    private static final String AUTH_SPNEGO = "Negotiate";
    private static final String HEADER_WWWAUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_ACCEPT_LANGUAGE = "Accept-Language";
    private static final String NTLM_AUTH_DETAILS = "_alfwfNTLMDetails";
    private static final String AUTH_BY_KERBEROS = "_alfAuthByKerberos";
    private static final String MIME_HTML_TEXT = "text/html";
    private static final String PAGE_SERVLET_PATH = "/page";
    private static final String LOGIN_PATH_INFORMATION = "/dologin";
    private static final String LOGIN_PARAMETER = "login";
    private static final String ERROR_PARAMETER = "error";
    private static final String UNAUTHENTICATED_ACCESS_PROXY = "/proxy/alfresco-noauth";
    private static final String PAGE_VIEW_RESOLVER = "pageViewResolver";
    private ApplicationContext context;
    private ConnectorService connectorService;
    private String endpoint;
    private String userHeader;
    private Pattern userIdPattern;
    private SlingshotLoginController loginController;
    private String krbAccountName;
    private String krbPassword;
    private String krbRealm;
    private String krbEndpointSPN;
    private String jaasLoginEntryName;
    private LoginContext jaasLoginContext;
    private boolean stripUserNameSuffix;

    private Wso2SecurityConfig wso2SecurityConfig;


    // Atributos para configuración de OAuth 2.0
    private String wso2IntrospectionEndpoint;  // URL del endpoint de introspección
    private String wso2ClientId;               // ID del cliente registrado en WSO2
    private String wso2ClientSecret;           // Secreto del cliente registrado en WSO2

    // Constantes para los nombres de las cookies requeridas
    private   String COOKIE_REMOTE_USER = "X-Alfresco-Remote-User";
    private   String COOKIE_ACCESS_TOKEN = "X-Access-Token";
    private   String COOKIE_ALFRESCO_TICKET = "Alfresco-Ticket";


    public EnTallaSSOAuthenticationFilter() {
        this.wso2SecurityConfig=Wso2SecurityConfig.create();
        COOKIE_REMOTE_USER=wso2SecurityConfig.getPropertyByKey("external.authentication.proxyHeader",COOKIE_REMOTE_USER);
        COOKIE_ACCESS_TOKEN=wso2SecurityConfig.getPropertyByKey("external.authentication.proxyTokenHeader",COOKIE_ACCESS_TOKEN);
        COOKIE_ALFRESCO_TICKET=wso2SecurityConfig.getPropertyByKey("external.authentication.proxyTicketHeader",COOKIE_ALFRESCO_TICKET);

    }

    /**
     * Valida un accessToken contra el endpoint de introspección de WSO2.
     *
     * @param token AccessToken proporcionado en las cookies.
     * @return true si el token es válido, false en caso contrario.
     */
    private boolean validateAccessToken(String token) {

        return false;
    }

    /**
     * Codifica las credenciales del cliente en formato Base64 para la autenticación.
     *
     * @return Credenciales codificadas.
     */
    private String encodeClientCredentials() {
        String credentials = wso2ClientId + ":" + wso2ClientSecret;
        return java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    /**
     * Comprueba las cookies necesarias para la autenticación OAuth 2.0.
     *
     * @param req HttpServletRequest recibido.
     * @return true si todas las cookies están presentes y válidas, false en caso contrario.
     */
    private boolean checkOAuthCookies(HttpServletRequest req) {
        String remoteUser = req.getHeader(COOKIE_REMOTE_USER);
        String accessToken = req.getHeader(COOKIE_ACCESS_TOKEN);
        String alfrescoTicket = req.getHeader(COOKIE_ALFRESCO_TICKET);

        if (remoteUser != null && accessToken != null && alfrescoTicket != null) {
            return validateAccessToken(accessToken);
        }

        return false;
    }


    public void init() {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing the SSOAuthenticationFilter.");
        }

        this.loginController = (SlingshotLoginController) this.context.getBean("loginController");
        this.connectorService = (ConnectorService)this.context.getBean("connector.service");
        ConfigService configService = (ConfigService)this.context.getBean("web.config");
        RemoteConfigElement remoteConfig = (RemoteConfigElement)configService.getConfig("Remote").getConfigElement("remote");
        if (remoteConfig == null) {
            logger.error("There is no Remote configuration element. This is required to use SSOAuthenticationFilter.");
        } else if (this.endpoint == null) {
            logger.error("There is no 'endpoint' property in the SSOAuthenticationFilter bean parameters. Cannot initialise filter.");
        } else {
            RemoteConfigElement.EndpointDescriptor endpointDescriptor = remoteConfig.getEndpointDescriptor(this.endpoint);
            if (endpointDescriptor != null && endpointDescriptor.getExternalAuth()) {
                try {
                    Connector conn = this.connectorService.getConnector(this.endpoint);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Endpoint is " + this.endpoint);
                    }

                    this.userHeader = conn.getConnectorSession().getParameter("userHeader");
                    String userIdPattern = conn.getConnectorSession().getParameter("userIdPattern");
                    if (userIdPattern != null) {
                        this.userIdPattern = Pattern.compile(userIdPattern);
                    }

                    if (logger.isDebugEnabled()) {
                        logger.debug("userHeader is " + this.userHeader);
                        logger.debug("userIdPattern is " + userIdPattern);
                    }
                } catch (ConnectorServiceException var6) {
                    logger.error("Unable to find connector " + endpointDescriptor.getConnectorId() + " for the endpoint " + this.endpoint, var6);
                }

                this.initKerberos(configService);
                if (logger.isInfoEnabled()) {
                    logger.info("SSOAuthenticationFilter initialised.");
                }

            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("No External Auth endpoint configured for " + this.endpoint);
                }

                this.endpoint = null;
            }
        }
    }

    private void initKerberos(ConfigService configService) {
        KerberosConfigElement config = (KerberosConfigElement)configService.getConfig("Kerberos").getConfigElement("kerberos");
        if (config != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Found configuration for Kerberos authentication.");
            }

            String krbRealm = config.getRealm();
            if (krbRealm != null && krbRealm.length() > 0) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Found Kerberos realm: " + krbRealm);
                }

                this.krbRealm = krbRealm;
                String srvPassword = config.getPassword();
                if (srvPassword != null && srvPassword.length() > 0) {
                    this.krbPassword = srvPassword;
                    String krbEndpointSPN = config.getEndpointSPN();
                    if (krbEndpointSPN == null || krbEndpointSPN.length() <= 0) {
                        throw new AlfrescoRuntimeException("endpoint service principal name not specified");
                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug("The Service Principal Name to use on the endpoint: " + krbEndpointSPN);
                        }

                        this.krbEndpointSPN = krbEndpointSPN;
                        String loginEntry = config.getLoginEntryName();
                        if (loginEntry != null) {
                            if (loginEntry.length() <= 0) {
                                throw new AlfrescoRuntimeException("Invalid login entry specified");
                            }

                            if (logger.isDebugEnabled()) {
                                logger.debug("The login configuration entry name to use: " + loginEntry);
                            }

                            this.jaasLoginEntryName = loginEntry;
                        }

                        boolean stripUserNameSuffix = config.getStripUserNameSuffix();
                        if (logger.isDebugEnabled()) {
                            logger.debug("The stripUserNameSuffix property is set to: " + stripUserNameSuffix);
                        }

                        this.stripUserNameSuffix = stripUserNameSuffix;

                        try {
                            this.jaasLoginContext = new LoginContext(this.jaasLoginEntryName, this);
                            this.jaasLoginContext.login();
                            if (logger.isDebugEnabled()) {
                                logger.debug("HTTP Kerberos login successful");
                            }
                        } catch (LoginException var10) {
                            if (logger.isErrorEnabled()) {
                                logger.error("HTTP Kerberos web filter error", var10);
                            }

                            throw new AlfrescoRuntimeException("Failed to login HTTP server service");
                        }

                        Subject subj = this.jaasLoginContext.getSubject();
                        Principal princ = (Principal)subj.getPrincipals().iterator().next();
                        this.krbAccountName = princ.getName();
                        if (logger.isDebugEnabled()) {
                            logger.debug("Logged on using principal " + this.krbAccountName);
                        }

                    }
                } else {
                    throw new AlfrescoRuntimeException("HTTP service account password not specified");
                }
            } else {
                throw new AlfrescoRuntimeException("Kerberos realm not specified");
            }
        }
    }

    public void setApplicationContext(ApplicationContext applicationContext) {
        this.context = applicationContext;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    protected ServletRequest wrapHeaderAuthenticatedRequest(ServletRequest sreq) {
        if (this.userHeader != null && sreq instanceof final HttpServletRequest req) {
            sreq = new HttpServletRequestWrapper(req) {
                public String getRemoteUser() {
                    String remoteUser = req.getHeader(EnTallaSSOAuthenticationFilter.this.userHeader);
                    if (remoteUser != null) {
                        if (!Base64.isBase64(remoteUser)) {
                            try {
                                remoteUser = new String(remoteUser.getBytes("ISO-8859-1"), "UTF-8");
                            } catch (UnsupportedEncodingException var3) {
                            }
                        }

                        remoteUser = this.extractUserFromProxyHeader(remoteUser);
                    } else {
                        remoteUser = super.getRemoteUser();
                    }

                    return remoteUser;
                }

                private String extractUserFromProxyHeader(String userId) {
                    if (EnTallaSSOAuthenticationFilter.this.userIdPattern == null) {
                        userId = userId.trim();
                    } else {
                        Matcher matcher = EnTallaSSOAuthenticationFilter.this.userIdPattern.matcher(userId);
                        if (!matcher.matches()) {
                            return null;
                        }

                        userId = matcher.group(1).trim();
                    }

                    return userId.length() == 0 ? null : userId;
                }
            };
        }

        return (ServletRequest)sreq;
    }

    public void doFilter(ServletContext context, ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        this.doFilter(request, response, chain);
    }

    public void doFilter(ServletRequest sreq, ServletResponse sresp, FilterChain chain) throws IOException, ServletException {

        // 1. Validar cookies para OAuth 2.0
        HttpServletRequest req = (HttpServletRequest) sreq;
        HttpServletResponse res = (HttpServletResponse) sresp;
        HttpSession session = req.getSession();
        boolean debug = logger.isDebugEnabled();


        if (checkOAuthCookies(req)) {
            String remoteUser = req.getHeader(COOKIE_REMOTE_USER);
            String alfrescoTicket = req.getHeader(COOKIE_ALFRESCO_TICKET);

            if (debug) {
                logger.debug("Autenticación OAuth 2.0 exitosa para el usuario: " + remoteUser);
            }

            // Configurar sesión y continuar el filtro
            session.setAttribute("_alf_USER_ID", remoteUser);
            session.setAttribute("Alfresco-Ticket", alfrescoTicket);
            chain.doFilter(sreq, sresp);
            return;
        }
        // 2. Si no hay cookies OAuth válidas, continuar con el flujo existente
        boolean skip = false;

        try {
            AIMSConfig aimsConfig = (AIMSConfig)this.context.getBean("aims.config");
            if (aimsConfig.isEnabled()) {
                skip = true;
            }
        } catch (BeansException var27) {
            if (logger.isErrorEnabled()) {
                logger.error(var27);
            }
        }

        if (skip) {
            chain.doFilter(sreq, sresp);
        } else {
            NDC.remove();
            NDC.push(Thread.currentThread().getName());
            debug = logger.isDebugEnabled();
            sreq = this.wrapHeaderAuthenticatedRequest(sreq);
            if (this.endpoint == null) {
                if (debug) {
                    logger.debug("There is no endpoint with external auth enabled.");
                }

                chain.doFilter(sreq, sresp);
            } else {

                if (req.getServletPath() != null && req.getServletPath().startsWith("/proxy/alfresco-noauth")) {
                    if (debug) {
                        logger.debug("SSO is by-passed for unauthenticated access endpoint.");
                    }

                    chain.doFilter(sreq, sresp);
                } else {
                    Log var10000;
                    String var10001;
                    if (debug) {
                        var10000 = logger;
                        var10001 = req.getRequestURI();
                        var10000.debug("Processing request " + var10001 + " SID:" + session.getId());
                    }

                    String pathInfo = req.getPathInfo();
                    if (!"/page".equals(req.getServletPath()) || !"/dologin".equals(pathInfo) && (pathInfo != null || !"login".equals(req.getParameter("pt")))) {
                        RequestContext context = null;

                        try {
                            context = RequestContextUtil.initRequestContext(this.context, req, true);
                        } catch (Exception var25) {
                            logger.error("Error calling initRequestContext", var25);
                            throw new ServletException(var25);
                        }

                        Page page = context.getPage();
                        if (page == null && pathInfo != null) {
                            PageViewResolver pageViewResolver = (PageViewResolver)this.context.getBean("pageViewResolver");
                            if (pageViewResolver != null) {
                                try {
                                    if (pageViewResolver.resolveViewName(pathInfo, (Locale)null) != null) {
                                        page = context.getPage();
                                    }
                                } catch (Exception var24) {
                                }
                            }
                        }

                        if (page != null && page.getAuthentication() == RequiredAuthentication.none) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Unauthenticated page requested - skipping auth filter...");
                            }

                            chain.doFilter(sreq, sresp);
                        } else {
                            String authHdr;
                            if (this.userHeader != null) {
                                authHdr = AuthenticationUtil.getUserId(req);
                                if (authHdr != null && req.getRemoteUser() != null) {
                                    if (logger.isDebugEnabled()) {
                                        logger.debug("userHeader external auth - skipping auth filter...");
                                    }

                                    this.setExternalAuthSession(session);
                                    this.onSuccess(req, res, session, req.getRemoteUser());
                                    chain.doFilter(sreq, sresp);
                                } else {
                                    this.challengeOrPassThrough(chain, req, res, session);
                                }
                            } else {
                                authHdr = req.getHeader("Authorization");
                                if (authHdr == null && AuthenticationUtil.isAuthenticated(req)) {
                                    if (debug) {
                                        logger.debug("Touching the repo to ensure we still have an authenticated session.");
                                    }

                                    this.challengeOrPassThrough(chain, req, res, session);
                                } else if (authHdr == null) {
                                    if (debug) {
                                        var10000 = logger;
                                        var10001 = req.getRemoteHost();
                                        var10000.debug("New auth request from " + var10001 + " (" + req.getRemoteAddr() + ":" + req.getRemotePort() + ")");
                                    }

                                    this.challengeOrPassThrough(chain, req, res, session);
                                } else {
                                    byte[] spnegoByts;
                                    if (authHdr.startsWith("Negotiate") && this.krbRealm != null) {
                                        if (debug) {
                                            logger.debug("Processing SPNEGO / Kerberos authentication.");
                                        }

                                        spnegoByts = org.springframework.extensions.surf.util.Base64.decode(authHdr.substring(10).getBytes());
                                        if (this.isNTLMSSPBlob(spnegoByts, 0)) {
                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Client sent an NTLMSSP security blob");
                                            }

                                            this.restartAuthProcess(session, req, res, "Negotiate");
                                            return;
                                        }

                                        int tokType = -1;

                                        try {
                                            tokType = SPNEGO.checkTokenType(spnegoByts, 0, spnegoByts.length);
                                        } catch (IOException var23) {
                                        }

                                        if (tokType == 0) {
                                            if (debug) {
                                                logger.debug("Parsing the SPNEGO security blob to get the Kerberos ticket.");
                                            }

                                            NegTokenInit negToken = new NegTokenInit();

                                            try {
                                                negToken.decode(spnegoByts, 0, spnegoByts.length);
                                                String oidStr = null;
                                                if (negToken.numberOfOids() > 0) {
                                                    oidStr = negToken.getOidAt(0).toString();
                                                }

                                                if (oidStr != null && (oidStr.equals("1.2.840.48018.1.2.2") || oidStr.equals("1.2.840.113554.1.2.2"))) {
                                                    if (debug) {
                                                        logger.debug("Kerberos logon.");
                                                    }

                                                    if (this.doKerberosLogon(negToken, req, res, session) != null) {
                                                        chain.doFilter(req, res);
                                                        if (logger.isDebugEnabled()) {
                                                            logger.debug("Request processing ended");
                                                        }
                                                    } else {
                                                        this.restartAuthProcess(session, req, res, "Negotiate");
                                                    }
                                                } else {
                                                    if (logger.isDebugEnabled()) {
                                                        logger.debug("Unsupported SPNEGO mechanism " + oidStr);
                                                    }

                                                    this.restartAuthProcess(session, req, res, "Negotiate");
                                                }
                                            } catch (IOException var26) {
                                                if (logger.isDebugEnabled()) {
                                                    logger.debug(var26);
                                                }
                                            }
                                        } else {
                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Unknown SPNEGO token type");
                                            }

                                            this.restartAuthProcess(session, req, res, "Negotiate");
                                        }
                                    } else if (authHdr.startsWith("NTLM")) {
                                        if (debug) {
                                            logger.debug("Processing NTLM authentication.");
                                        }

                                        spnegoByts = authHdr.substring(5).getBytes();
                                        byte[] ntlmByts = org.springframework.extensions.surf.util.Base64.decode(spnegoByts);
                                        int ntlmTyp = NTLMMessage.isNTLMType(ntlmByts);
                                        Object sessionMutex = WebUtils.getSessionMutex(session);
                                        if (ntlmTyp == 1) {
                                            if (debug) {
                                                logger.debug("Process the type 1 NTLM message.");
                                            }

                                            Type1NTLMMessage type1Msg = new Type1NTLMMessage(ntlmByts);
                                            synchronized(sessionMutex) {
                                                this.processType1(type1Msg, req, res, session);
                                            }
                                        } else if (ntlmTyp == 3) {
                                            if (debug) {
                                                logger.debug("Process the type 3 NTLM message.");
                                            }

                                            Type3NTLMMessage type3Msg = new Type3NTLMMessage(ntlmByts);
                                            synchronized(sessionMutex) {
                                                this.processType3(type3Msg, req, res, session, chain);
                                            }
                                        } else {
                                            if (debug) {
                                                logger.debug("NTLM not handled, redirecting to login page");
                                            }

                                            this.redirectToLoginPage(req, res);
                                        }
                                    } else {
                                        if (debug) {
                                            logger.debug("Processing Basic Authentication.");
                                        }

                                        if (!AuthenticationUtil.isAuthenticated(req) && req.getRemoteUser() == null) {
                                            if (debug) {
                                                logger.debug("Establish a new session or bring up the login page.");
                                            }

                                            chain.doFilter(req, res);
                                        } else {
                                            if (debug) {
                                                logger.debug("Ensuring the session is still valid.");
                                            }

                                            this.challengeOrPassThrough(chain, req, res, session);
                                        }
                                    }

                                }
                            }
                        }
                    } else {
                        if (debug) {
                            logger.debug("Login page requested, chaining ...");
                        }

                        chain.doFilter(sreq, sresp);
                    }
                }
            }
        }
    }

    private void clearSession(HttpSession session) {
        if (logger.isDebugEnabled()) {
            logger.debug("Clearing the session.");
        }

        Enumeration<String> names = session.getAttributeNames();

        while(names.hasMoreElements()) {
            session.removeAttribute((String)names.nextElement());
        }

    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (logger.isDebugEnabled()) {
            logger.debug("Processing the JAAS callback list of " + callbacks.length + " items.");
        }

        for(int i = 0; i < callbacks.length; ++i) {
            if (callbacks[i] instanceof NameCallback) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Request for user name.");
                }

                NameCallback cb = (NameCallback)callbacks[i];
                cb.setName(this.krbAccountName);
            } else if (callbacks[i] instanceof PasswordCallback) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Request for password.");
                }

                PasswordCallback cb = (PasswordCallback)callbacks[i];
                cb.setPassword(this.krbPassword.toCharArray());
            } else {
                if (!(callbacks[i] instanceof RealmCallback)) {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }

                if (logger.isDebugEnabled()) {
                    logger.debug("Request for realm.");
                }

                RealmCallback cb = (RealmCallback)callbacks[i];
                cb.setText(this.krbRealm);
            }
        }

    }

    private void challengeOrPassThrough(FilterChain chain, HttpServletRequest req, HttpServletResponse res, HttpSession session) throws IOException, ServletException {
        try {
            String userId = AuthenticationUtil.getUserId(req);
            if (userId == null) {
                userId = req.getRemoteUser();
                session.setAttribute("_alfExternalAuth", Boolean.TRUE);
                if (userId != null && logger.isDebugEnabled()) {
                    logger.debug("Initial login from externally authenticated user " + userId);
                }

                if (userId == null && this.krbRealm == null) {
                    this.redirectToLoginPage(req, res);
                }
            } else if (logger.isDebugEnabled()) {
                logger.debug("Validating repository session for " + userId);
            }

            if (userId != null && !userId.equalsIgnoreCase(req.getRemoteUser()) && session.getAttribute("_alfwfNTLMDetails") == null && session.getAttribute("_alfAuthByKerberos") == null) {
                session.removeAttribute("_alfExternalAuth");
            }

            Connector conn = this.connectorService.getConnector(this.endpoint, userId, session);
            ConnectorContext ctx;
            if (req.getHeader("Accept-Language") != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Accept-Language header present: " + req.getHeader("Accept-Language"));
                }

                ctx = new ConnectorContext((Map)null, Collections.singletonMap("Accept-Language", req.getHeader("Accept-Language")));
            } else {
                ctx = new ConnectorContext();
            }

            Response remoteRes = conn.call("/touch", ctx);
            if (401 == remoteRes.getStatus().getCode()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Repository session timed out - restarting auth process...");
                }

                String authHdr = (String)remoteRes.getStatus().getHeaders().get("WWW-Authenticate");
                if (authHdr != null) {
                    this.restartAuthProcess(session, req, res, authHdr);
                } else {
                    if (req.getRemoteUser() == null) {
                        try {
                            session.invalidate();
                        } catch (IllegalStateException var11) {
                        }
                    }

                    this.redirectToLoginPage(req, res);
                }

            } else {
                this.onSuccess(req, res, session, userId);
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication not required, chaining ...");
                }

                chain.doFilter(req, res);
            }
        } catch (ConnectorServiceException var12) {
            throw new PlatformRuntimeException("Incorrectly configured endpoint ID: " + this.endpoint);
        }
    }

    public void destroy() {
    }

    private Map<String, String> getConnectionHeaders(Connector conn) {
        Map<String, String> headers = new HashMap(4);
        headers.put("user-agent", "");
        if (conn.getConnectorSession().getCookie("JSESSIONID") == null) {
            headers.put("Cookie",null);
        }

        headers.put("Content-Type", null);
        headers.put("Content-Length", null);
        return headers;
    }

    private void restartAuthProcess(HttpSession session, HttpServletRequest req, HttpServletResponse res, String authHdr) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Restarting " + authHdr + " authentication.");
        }

        this.clearSession(session);
        this.setRedirectUrl(req);
        res.setHeader("WWW-Authenticate", authHdr);
        res.setStatus(401);
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        out.println("<html><head>");
        out.println("<meta http-equiv=\"Refresh\" content=\"0; url=" + req.getContextPath() + "/page?pt=login\">");
        out.println("</head><body><p>Please <a href=\"" + req.getContextPath() + "/page?pt=login\">log in</a>.</p>");
        out.println("</body></html>");
        out.close();
        res.flushBuffer();
    }

    private void processType1(Type1NTLMMessage type1Msg, HttpServletRequest req, HttpServletResponse res, HttpSession session) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Received type1 " + type1Msg);
        }

        NTLMLogonDetails ntlmDetails = (NTLMLogonDetails)session.getAttribute("_alfwfNTLMDetails");
        String var10000;
        if (ntlmDetails != null && ntlmDetails.hasType2Message()) {
            Type2NTLMMessage cachedType2 = ntlmDetails.getType2Message();
            byte[] type2Bytes = cachedType2.getBytes();
            var10000 = new String(org.springframework.extensions.surf.util.Base64.encodeBytes(type2Bytes, 8));
            String ntlmBlob = "NTLM " + var10000;
            if (logger.isDebugEnabled()) {
                logger.debug("Sending cached NTLM type2 to client - " + cachedType2);
            }

            res.setHeader("WWW-Authenticate", ntlmBlob);
            res.setStatus(401);
            res.flushBuffer();
        } else {
            session.removeAttribute("_alfwfNTLMDetails");

            try {
                Connector conn = this.connectorService.getConnector(this.endpoint, session);
                ConnectorContext ctx = new ConnectorContext((Map)null, this.getConnectionHeaders(conn));
                Response remoteRes = conn.call("/touch", ctx, req, (HttpServletResponse)null);
                if (401 == remoteRes.getStatus().getCode()) {
                    String authHdr = (String)remoteRes.getStatus().getHeaders().get("WWW-Authenticate");
                    if (authHdr.startsWith("NTLM") && authHdr.length() > 4) {
                        byte[] authHdrByts = authHdr.substring(5).getBytes();
                        byte[] ntlmByts = org.springframework.extensions.surf.util.Base64.decode(authHdrByts);
                        int ntlmType = NTLMMessage.isNTLMType(ntlmByts);
                        if (ntlmType == 2) {
                            Type2NTLMMessage type2Msg = new Type2NTLMMessage(ntlmByts);
                            ntlmDetails = new NTLMLogonDetails();
                            ntlmDetails.setType2Message(type2Msg);
                            session.setAttribute("_alfwfNTLMDetails", ntlmDetails);
                            if (logger.isDebugEnabled()) {
                                logger.debug("Sending NTLM type2 to client - " + type2Msg);
                            }

                            byte[] type2Bytes = type2Msg.getBytes();
                            var10000 = new String(org.springframework.extensions.surf.util.Base64.encodeBytes(type2Bytes, 8));
                            String ntlmBlob = "NTLM " + var10000;
                            res.setHeader("WWW-Authenticate", ntlmBlob);
                            res.setStatus(401);
                            res.flushBuffer();
                        } else {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Unexpected NTLM message type from repository: NTLMType" + ntlmType);
                            }

                            this.redirectToLoginPage(req, res);
                        }
                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Unexpected response from repository: WWW-Authenticate:" + authHdr);
                        }

                        this.redirectToLoginPage(req, res);
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Unexpected response from repository: " + remoteRes.getStatus().getMessage());
                    }

                    this.redirectToLoginPage(req, res);
                }
            } catch (ConnectorServiceException var16) {
                throw new PlatformRuntimeException("Incorrectly configured endpoint ID: " + this.endpoint);
            }
        }

    }

    private void processType3(Type3NTLMMessage type3Msg, HttpServletRequest req, HttpServletResponse res, HttpSession session, FilterChain chain) throws IOException, ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("Received type3 " + type3Msg);
        }

        NTLMLogonDetails ntlmDetails = (NTLMLogonDetails)session.getAttribute("_alfwfNTLMDetails");
        String userId = AuthenticationUtil.getUserId(req);
        String userName = type3Msg.getUserName();
        String workstation = type3Msg.getWorkstation();
        String domain = type3Msg.getDomain();
        boolean authenticated = false;
        if (userId != null && ntlmDetails != null && ntlmDetails.hasNTLMHashedPassword()) {
            byte[] ntlmPwd = type3Msg.getNTLMHash();
            byte[] cachedPwd = ntlmDetails.getNTLMHashedPassword();
            if (ntlmPwd != null && ntlmPwd.length == cachedPwd.length) {
                authenticated = true;

                for(int i = 0; i < ntlmPwd.length; ++i) {
                    if (ntlmPwd[i] != cachedPwd[i]) {
                        authenticated = false;
                        break;
                    }
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Using cached NTLM hash, authenticated = " + authenticated);
            }

            if (!authenticated) {
                this.restartAuthProcess(session, req, res, "NTLM");
            } else {
                chain.doFilter(req, res);
            }
        } else {
            try {
                Connector conn = this.connectorService.getConnector(this.endpoint, session);
                ConnectorContext ctx = new ConnectorContext((Map)null, this.getConnectionHeaders(conn));
                Response remoteRes = conn.call("/touch", ctx, req, (HttpServletResponse)null);
                if (401 == remoteRes.getStatus().getCode()) {
                    String authHdr = (String)remoteRes.getStatus().getHeaders().get("WWW-Authenticate");
                    if (authHdr.equals("NTLM")) {
                        String userAgent = req.getHeader("user-agent");
                        if (userAgent != null && userAgent.indexOf("Safari") != -1 && userAgent.indexOf("Chrome") == -1) {
                            res.setStatus(401);
                            PrintWriter out = res.getWriter();
                            out.println("<html><head></head>");
                            out.println("<body><p>Login authentication failed. Please close and re-open Safari to try again.</p>");
                            out.println("</body></html>");
                            out.close();
                        } else {
                            this.restartAuthProcess(session, req, res, authHdr);
                        }

                        res.flushBuffer();
                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Unexpected response from repository: WWW-Authenticate:" + authHdr);
                        }

                        this.redirectToLoginPage(req, res);
                    }
                } else if (200 != remoteRes.getStatus().getCode() && 307 != remoteRes.getStatus().getCode()) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Unexpected response from repository: " + remoteRes.getStatus().getMessage());
                    }

                    this.redirectToLoginPage(req, res);
                } else {
                    if (ntlmDetails == null) {
                        ntlmDetails = new NTLMLogonDetails(userName, workstation, domain, false, (String)null);
                        ntlmDetails.setNTLMHashedPassword(type3Msg.getNTLMHash());
                        session.setAttribute("_alfwfNTLMDetails", ntlmDetails);
                        if (logger.isDebugEnabled()) {
                            logger.debug("No cached NTLM details, created");
                        }
                    } else {
                        ntlmDetails.setDetails(userName, workstation, domain, false, (String)null);
                        ntlmDetails.setNTLMHashedPassword(type3Msg.getNTLMHash());
                        if (logger.isDebugEnabled()) {
                            logger.debug("Updated cached NTLM details");
                        }
                    }

                    if (logger.isDebugEnabled()) {
                        logger.debug("User logged on via NTLM, " + ntlmDetails);
                    }

                    this.setExternalAuthSession(session);
                    this.onSuccess(req, res, session, userName);
                    chain.doFilter(req, res);
                }
            } catch (ConnectorServiceException var18) {
                throw new PlatformRuntimeException("Incorrectly configured endpoint: " + this.endpoint);
            }
        }

    }

    private void redirectToLoginPage(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to the login page.");
        }

        if ("/page".equals(req.getServletPath())) {
            this.setRedirectUrl(req);
            String error = req.getParameter("error");
            String var10001 = req.getContextPath();
            res.sendRedirect(var10001 + "/page?pt=login" + (error == null ? "" : "&error=" + error));
        } else {
            res.setStatus(401);
            res.flushBuffer();
        }

    }

    private boolean isNTLMSSPBlob(byte[] byts, int offset) {
        boolean isNTLMSSP = false;
        if (byts.length - offset >= NTLM.Signature.length) {
            if (logger.isDebugEnabled()) {
                logger.debug("Checking if the blob has the NTLMSSP signature.");
            }

            int idx;
            for(idx = 0; idx < NTLM.Signature.length && byts[offset + idx] == NTLM.Signature[idx]; ++idx) {
            }

            if (idx == NTLM.Signature.length) {
                isNTLMSSP = true;
            }
        }

        return isNTLMSSP;
    }

    private NegTokenTarg doKerberosLogon(NegTokenInit negToken, HttpServletRequest req, HttpServletResponse resp, HttpSession httpSess) {
        KerberosDetails krbDetails = null;
        NegTokenTarg negTokenTarg = null;

        try {
            KerberosSessionSetupPrivilegedAction sessSetupAction = new KerberosSessionSetupPrivilegedAction(this.krbAccountName, negToken.getMechtoken(), this.krbEndpointSPN);
            Object result = Subject.doAs(this.jaasLoginContext.getSubject(), sessSetupAction);
            if (result != null) {
                Pair<KerberosDetails, String> resultPair = (Pair)result;
                krbDetails = (KerberosDetails)resultPair.getFirst();
                String tokenForEndpoint = (String)resultPair.getSecond();
                negTokenTarg = new NegTokenTarg(0, OID.KERBEROS5, krbDetails.getResponseToken());
                if (negTokenTarg != null) {
                    String userName = this.stripUserNameSuffix ? krbDetails.getUserName() : krbDetails.getSourceName();
                    if (logger.isDebugEnabled()) {
                        logger.debug("User " + userName + " logged on via Kerberos; attempting to log on to Alfresco then");
                    }

                    boolean authenticated = this.doKerberosDelegateLogin(req, resp, httpSess, userName, tokenForEndpoint);
                    if (!authenticated) {
                        return null;
                    }

                    httpSess.setAttribute("_alfAuthByKerberos", true);
                }
            } else if (logger.isDebugEnabled()) {
                logger.debug("No SPNEGO response, Kerberos logon failed");
            }
        } catch (Exception var13) {
            if (logger.isDebugEnabled()) {
                logger.debug("Kerberos logon error", var13);
            }
        }

        return negTokenTarg;
    }

    private boolean doKerberosDelegateLogin(HttpServletRequest req, HttpServletResponse res, HttpSession session, String userName, String tokenForEndpoint) throws IOException {
        try {
            Connector conn = this.connectorService.getConnector(this.endpoint, session);
            ConnectorContext ctx;
            if (req.getHeader("Accept-Language") != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Accept-Language header present: " + req.getHeader("Accept-Language"));
                }

                Map<String, String> headers = new HashMap(7);
                headers.put("Accept-Language", req.getHeader("Accept-Language"));
                ctx = new ConnectorContext((Map)null, headers);
            } else {
                ctx = new ConnectorContext();
            }

            Response remoteRes = conn.call("/touch", ctx);
            if (401 == remoteRes.getStatus().getCode()) {
                String authHdr = (String)remoteRes.getStatus().getHeaders().get("WWW-Authenticate");
                if (!authHdr.equals("Negotiate")) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Unexpected response from repository: WWW-Authenticate:" + authHdr);
                    }

                    return false;
                }

                Map<String, String> headers = new HashMap(7);
                headers.put("Authorization", "Negotiate " + tokenForEndpoint);
                if (req.getHeader("Accept-Language") != null) {
                    headers.put("Accept-Language", req.getHeader("Accept-Language"));
                }

                ctx = new ConnectorContext((Map)null, headers);
                remoteRes = conn.call("/touch", ctx);
                if (200 != remoteRes.getStatus().getCode() && 307 != remoteRes.getStatus().getCode()) {
                    if (401 == remoteRes.getStatus().getCode()) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Authentication failed on repo side - beging login process again.");
                        }

                        res.setHeader("WWW-Authenticate", authHdr);
                        res.setStatus(401);
                        res.flushBuffer();
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Authentication succeeded on the repo side.");
                    }

                    this.setExternalAuthSession(session);
                    this.onSuccess(req, res, session, userName);
                }
            } else {
                if (200 != remoteRes.getStatus().getCode() && 307 != remoteRes.getStatus().getCode()) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Unexpected response from repository: " + remoteRes.getStatus().getMessage());
                    }

                    return false;
                }

                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication succeeded on the repo side.");
                }

                this.setExternalAuthSession(session);
                this.onSuccess(req, res, session, userName);
            }

            return true;
        } catch (ConnectorServiceException var11) {
            throw new AlfrescoRuntimeException("Incorrectly configured endpoint: " + this.endpoint);
        }
    }

    private void setRedirectUrl(HttpServletRequest req) {
        HttpSession session = req.getSession();
        session.setAttribute("_redirectURI", req.getRequestURI());
        if (req.getQueryString() != null) {
            session.setAttribute("_redirectQueryString", req.getQueryString());
        }

    }

    private void setExternalAuthSession(HttpSession session) {
        session.setAttribute("_alfExternalAuth", Boolean.TRUE);
    }

    private void onSuccess(HttpServletRequest req, HttpServletResponse res, HttpSession session, String username) {
        session.setAttribute("_alf_USER_ID", username);

        try {
            this.loginController.beforeSuccess(req, res);
        } catch (Exception var6) {
            throw new AlfrescoRuntimeException("Error during loginController.onSuccess()", var6);
        }
    }





}

