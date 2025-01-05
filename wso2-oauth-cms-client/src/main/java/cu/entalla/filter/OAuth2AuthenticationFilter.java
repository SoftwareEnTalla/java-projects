package cu.entalla.filter;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;

import cu.entalla.security.EnTallaTrustManager;
import cu.entalla.security.TrustSpecificHostsManager;
import cu.entalla.security.client.oauth2.OAuth2PKCEClient;
import cu.entalla.service.AuthenticationService;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.store.CookieManager;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@WebFilter("/alfresco/*")
public class OAuth2AuthenticationFilter implements Filter {

    private Wso2SecurityConfig wso2SecConfig;
    private AuthenticationService authService=new AuthenticationService();

    private EnTallaTrustManager trustManager;

    private static final Logger logger = Logger.getLogger(OAuth2AuthenticationFilter.class.getName());

    private static String redirectPage="/alfresco";

    public static String getRedirectPage(){
        return redirectPage;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        try {
            redirectPage=filterConfig.getInitParameter("redirectPage");
            if(redirectPage==null||redirectPage!=null && !redirectPage.isEmpty())
                redirectPage="/alfresco";
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(filterConfig.getServletContext());
            SpringContextHolder.setApplicationContext(redirectPage,webApplicationContext);
            SpringContextHolder.registry(redirectPage,webApplicationContext);

            // Obtener el valor de CATALINA_BASE
            String catalinaBase = System.getenv("CATALINA_BASE");
            if(catalinaBase==null) {
                catalinaBase = filterConfig.getInitParameter("CATALINA_BASE");// "/media/datos/Instaladores/entalla/tomcat";
                System.setProperty("CATALINA_BASE",catalinaBase);
            }
            if(catalinaBase!=null)
            {
                String configFilePath = catalinaBase+"/shared/classes/alfresco-global.properties";
                Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFilePath);
                this.wso2SecConfig = new Wso2SecurityConfig(configFilePath);
                String tomcatTrustStoreFilePath =  this.wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.location",null);
                String tomcatTrustStorePass = this.wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.password",null);
                String keyStoreType = wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.type", "JCEKS");
                logger.info("Cargando certificados de confianza de tomcat:"+tomcatTrustStoreFilePath);
                if(tomcatTrustStoreFilePath!=null && tomcatTrustStorePass!=null)
                    loadHostManager(tomcatTrustStoreFilePath,tomcatTrustStorePass,keyStoreType);

                String wso2isTrustStoreFilePath =  this.wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.location",null);
                String wso2isTrustStorePass = this.wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.password",null);
                keyStoreType = wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.type", "JKS");
                logger.info("Cargando certificados de confianza de wso2is:"+wso2isTrustStoreFilePath);
                if(wso2isTrustStoreFilePath!=null && wso2isTrustStorePass!=null)
                    loadHostManager(wso2isTrustStoreFilePath,wso2isTrustStorePass,keyStoreType);
                AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
                if(trustManager!=null){
                    AuthenticationStore.getInstance().setTrustManager(trustManager);
                }
                AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void inicialize(String catalinaHome,String relativeConfigFile){
        String configFilePath = catalinaHome + "shared/classes/" + relativeConfigFile;
        logger.info("Cargando configuración desde: " + configFilePath);
        this.wso2SecConfig = new Wso2SecurityConfig(configFilePath);
        try {
            String tomcatTrustStoreFilePath =  this.wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.location",null);
            String tomcatTrustStorePass = this.wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.password",null);
            String keyStoreType = wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.type", "JCEKS");
            logger.info("Cargando certificados de confianza de tomcat:"+tomcatTrustStoreFilePath);
            if(tomcatTrustStoreFilePath!=null && tomcatTrustStorePass!=null)
                loadHostManager(tomcatTrustStoreFilePath,tomcatTrustStorePass,keyStoreType);

            String wso2isTrustStoreFilePath =  this.wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.location",null);
            String wso2isTrustStorePass = this.wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.password",null);
            keyStoreType = wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.type", "JKS");
            logger.info("Cargando certificados de confianza de wso2is:"+wso2isTrustStoreFilePath);
            if(wso2isTrustStoreFilePath!=null && wso2isTrustStorePass!=null)
                loadHostManager(wso2isTrustStoreFilePath,wso2isTrustStorePass,keyStoreType);

        } catch (KeyStoreException ke) {
            ke.fillInStackTrace();
            throw new RuntimeException(ke);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
        if(trustManager!=null){
            AuthenticationStore.getInstance().setTrustManager(trustManager);
        }
        AuthenticationStore.getInstance().setWso2SecurityConfig(this.wso2SecConfig);
    }
    private void loadHostManager(String trustStoreFilePath,String trustStorePass,String keyStoreType) throws KeyStoreException, FileNotFoundException {

        if(new File(trustStoreFilePath).exists()){
            // Configurar los hosts permitidos y sus alias en el KeyStore
            Map<String, String> hostAliases = new HashMap<>();
            hostAliases.put("ses-idp.entalla.cu", "ses-idp.entalla.cu");
            hostAliases.put("ses-cms.entalla.cu", "ssl.repo");
            logger.info("Los HostAliases han sido inicializados con "+hostAliases.size()+" elementos...");
            // Cargar el KeyStore
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            logger.info("Abriendo "+trustStoreFilePath+" para carga inicial...");
            try (FileInputStream fis = new FileInputStream(trustStoreFilePath)) {
                keyStore.load(fis, trustStorePass.toCharArray());
                logger.info("KeyStore cargado desde "+trustStoreFilePath+" satisfactoriamente...");
                // Crear el mapa de hosts confiables
                logger.info("Iniciando trustedHosts con los hostAliases...");
                Map<String, Certificate> trustedHosts = TrustSpecificHostsManager.loadTrustedHosts(keyStore, hostAliases);

                // Crear el TrustManager personalizado
                if(trustManager==null){
                    logger.info("Iniciando trustManager con los trustedHosts...");
                    trustManager =  new TrustSpecificHostsManager(trustedHosts);
                }
                else {
                    logger.info("Adicionando  trustedHosts al  trustManager ya iniciado...");
                    trustManager=trustManager.addTrustedHosts(trustedHosts);
                }

            } catch (CertificateException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (IOException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (Exception e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {


        CookieManager manager= cu.entalla.store.CookieManager.getInstance().setRequest((HttpServletRequest) request).setResponse((HttpServletResponse) response);

        String error = manager.getParameter("error");

        // Manejo de errores
        if (error != null) {
            String errorDescription = manager.getParameter("error_description");
            System.err.println("Error en la autenticación: " + error + " - " + errorDescription);
            manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error en la autenticación: " + errorDescription);
            return;
        }
        //String codeVerifier = this.wso2SecConfig.generateCodeVerifier();
        manager.setAttribute("globalProperty", this.wso2SecConfig.getGlobalPropertyFile(),true);
        // Generar Code Verifier y Code Challenge
        Object savedCodeVerifier=manager.getAttribute("code_verifier");
        // Generar Code Verifier o cogerlo de sessión
        String codeVerifier =savedCodeVerifier!=null?savedCodeVerifier.toString(): AuthenticationStore.getInstance().getWso2SecurityConfig().generateCodeVerifier();
        // Almacenar el code_verifier en la sesión para el intercambio posterior
        manager.setAttribute("code_verifier",codeVerifier,true);
        // Generar Code Challenge
        String codeChallenge = this.wso2SecConfig.generateCodeChallenge(codeVerifier);

        String uri = manager.getRequestURI();
        boolean authenticated = isAuthenticated(manager.getRequest());
        logger.info("Usuario autenticado:"+authenticated);

        System.out.println("URI interceptada: " + manager.getRequestURI());
        System.out.println("Configuración de Alfresco: " + this.wso2SecConfig.getGlobalPropertyFile());
        System.out.println("Usuario autenticado: " + authenticated);
        // Manejo del Callback
        if (authenticated && (uri.startsWith("/alfresco/wso2/oauth2/callback") || uri.startsWith("/share/wso2/oauth2/callback"))) {
            System.out.println("Navegando al CallBack: " + authenticated);
            String code = manager.getParameter("code");
            codeVerifier = (String) manager.getAttribute("code_verifier");
            if (code == null || codeVerifier == null) {
                manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid PKCE flow");
                return;
            }
            try {
                OAuth2AccessTokenResponse tokenResponse = new AuthenticationService().getAccessToken(code, codeVerifier);
            } catch (Exception e) {
                throw new ServletException(e);
            }
            // Manejar el callback del proveedor de identidad
            chain.doFilter(request, response);
            return;
        }

        ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
        boolean withPAR=this.wso2SecConfig.getParEnable();
        logger.info("URI:"+uri);
        logger.info("startsWith /alfresco/wso2/oauth2/login:"+uri.startsWith("/alfresco/wso2/oauth2/login"));
        logger.info("startsWith /share/wso2/oauth2/login:"+uri.startsWith("/share/wso2/oauth2/login"));
        logger.info("withPAR:"+withPAR);
        // Si no está autenticado y está en la URL de login, redirigir con PAR
        if (!authenticated && (uri.startsWith("/alfresco/wso2/oauth2/login") || uri.startsWith("/share/wso2/oauth2/login"))) {
            logger.info("Navegando al login: " + uri);
            // Almacenar Code Verifier en la sesión del usuario
            manager.setAttribute("code_verifier", codeVerifier);
            // Obtener el request_uri
            try {
                OAuth2PKCEClient client=new OAuth2PKCEClient(wso2SecConfig);
                String result = client.authenticate(null);
                logger.info("AuthenticateResult: " + result);
                return;
            } catch (Exception e) {
                e.printStackTrace();
                manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error al obtener el request_uri "+(withPAR?" utilizando PAR":" sin utilizar PAR")+": " + e.getMessage());
                return;
            }
        }
        // Si no está autenticado, redirigir al proveedor de identidad con parámetros estándar (sin PAR)
        if (!authenticated) {
            logger.info("Navegando a uri= " + uri);
            // Obtener el request_uri
            try {
                OAuth2PKCEClient client=new OAuth2PKCEClient(wso2SecConfig);
                String result = client.authenticate(null);
                logger.info("AuthenticateResult: " + result);
                return;
            } catch (Exception e) {
                logger.info("ERROR:"+e.getMessage());
                e.printStackTrace();
                manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error al obtener el request_uri usando PAR: " + e.getMessage());
                return;
            }
        }
        // Continuar con la cadena de filtros si está autenticado
        chain.doFilter(request, response);
    }

    private boolean isAuthenticated(HttpServletRequest request) {
        // Verificar si el usuario ya está autenticado
        String user = (String) request.getSession().getAttribute("X-Alfresco-Remote-User");
        return user != null;
    }

    @Override
    public void destroy() {
        // Limpiar recursos si es necesario
    }
}
