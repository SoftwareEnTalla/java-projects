package cu.entalla.config;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.ConnectionChecker;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.model.OpenIDConfiguration;
import cu.entalla.serializer.*;
import cu.entalla.service.AuthenticationService;
import cu.entalla.service.ServiceLocator;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.udi.AlfrescoIntegration;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.context.ContextLoader;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.Random;
import java.util.logging.Logger;

@Configuration
@Data
public class Wso2SecurityConfig {

    @Value("${oauth2.client.registration.wso2.client-id}")
    private String clientId;

    @Value("${oauth2.client.registration.wso2.client-secret}")
    private String clientSecret;

    @Value("${oauth2.client.registration.wso2.scope}")
    private String scope;

    @Value("${oauth2.client.provider.wso2.issuer-uri}")
    private String issuerUri;

    @Value("${oauth2.client.registration.wso2.redirect-uri}")
    private String redirectUri;

    @Value("${oauth2.client.registration.wso2.authorization-grant-type}")
    private String authorizationGrantType;

    @Value("${oauth2.client.registration.wso2.client-authentication-method}")
    private String clientAuthenticationMethod;

    @Value("${oauth2.client.provider.wso2.authorization-uri}")
    private String authorizationUri;

    @Value("${oauth2.client.provider.wso2.token-uri}")
    private String tokenUri;

    @Value("${oauth2.client.provider.wso2.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${oauth2.client.provider.wso2.user-info-uri}")
    private String userInfoUri;

    @Value("${oauth2.client.provider.wso2.par-enabled}")
    private boolean parEnable=true;

    @Value("${oauth2.client.provider.wso2.par-uri}")
    private String parUri="false";

    @Value("oauth2.client.registration.wso2.private-key")
    private String privateKeyPath;

    @Value("oauth2.client.provider.wso2.pkce-flow")
    private String pkceFlow;

    @Value("oauth2.client.registration.wso2.responseType")
    private String responseType;

    @Value("oauth2.client.registration.wso2.login-hint")
    private String loginHint;

    @Value("oauth2.client.provider.wso2.introspect")
    private String instrospec;

    private boolean loaded =false;

    private Properties properties = new Properties();

    private String globalPropertyFile;


   
    // Constructor para inicializar con la ruta del archivo de configuración
    public Wso2SecurityConfig(String configFilePath) {
        globalPropertyFile=configFilePath;
        loaded=false;
    }
    public Wso2SecurityConfig() {
        loaded=false;
        Wso2SecurityConfig.create();
    }
    public static Logger getLogger(){
        return  Logger.getLogger(Wso2SecurityConfig.class.getName());
    }
    public static Wso2SecurityConfig create(){
        Wso2SecurityConfig wso2SecurityConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
        if(wso2SecurityConfig!=null) {
            return wso2SecurityConfig.isLoaded()?wso2SecurityConfig:wso2SecurityConfig.loadProperties();
        }
        String catalinaBase = System.getenv("CATALINA_BASE");
        if(catalinaBase==null) {
            catalinaBase = "/media/datos/Instaladores/entalla/tomcat";
            System.setProperty("CATALINA_BASE",catalinaBase);
        }
        if(catalinaBase!=null && wso2SecurityConfig==null){
            getLogger().info("CATALINA_BASE ON OAuth2CallbackServlet="+catalinaBase);
            catalinaBase+=(catalinaBase.endsWith("/")?"":"/");
            String configFilePath = catalinaBase + "shared/classes/alfresco-global.properties";
            getLogger().info("WSO2_CONFIG_FILE="+configFilePath);
            AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecurityConfig=new Wso2SecurityConfig(configFilePath).loadProperties());
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFilePath);
            AuthenticationService authService=new AuthenticationService(client);
            //Wso2SecurityConfig tmp=AuthenticationStore.getInstance().getWso2SecurityConfig();
            //Wso2SecurityConfig wso2SecurityConfig = tmp.loadProperties();
            //AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecurityConfig);
        }
        return AuthenticationStore.getInstance().getWso2SecurityConfig();
    }
    /*@Bean
    public PersonService personService() {
        return (PersonService) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(PersonService.class.getName());
    }
    @Bean
    public NodeService getNodeService() {
        return (NodeService) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(NodeService.class.getName());
    }
    @Bean
    public ServiceRegistry serviceRegistry() {
        // Aquí estamos obteniendo el ServiceRegistry directamente desde Alfresco
        return (ServiceRegistry) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(ServiceRegistry.class.getName());
    }*/
   /* @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        SpringContextHolder.setApplicationContext(WebApplicationContextUtils.getWebApplicationContext(ContextLoader.getCurrentWebApplicationContext().getServletContext()));
        return SpringContextHolder.getApplicationContext().getBean(org.springframework.security.authentication.dao.DaoAuthenticationProvider.class);
    }*/

    @Bean
    public HazelcastInstance hazelcastInstance(){

        getLogger().info("Hazelcast Config created... ");
        Wso2SecurityConfig conf=AuthenticationStore.getInstance().getWso2SecurityConfig();
        if(conf==null) {
            conf = Wso2SecurityConfig.create();
            if (!conf.isLoaded())
                conf.loadProperties();
            AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
        }
        // Crear instancia de Hazelcast con la configuración cargada
        String instanceName=conf.getPropertyByKey("hazelcast.instance.instanceName", "softwarentalla-hazelcast-instance");
        // Nombre del archivo en la ruta del classpath
        String configFileName =conf.getPropertyByKey("hazelcast.instance.classPathFileName", "alfresco/extension/hazelcastConfig.xml");;
        // Cargar configuración desde el classpath
        Config config = new ClasspathXmlConfig(configFileName);
        config.setInstanceName(instanceName);
        config.getSerializationConfig()
                .getCompactSerializationConfig()
                .addSerializer(new DefaultListableBeanFactorySerializer())
                .addSerializer(new XmlWebApplicationContextSerializer())
                .addSerializer(new AtomicBooleanSerializer()).addSerializer(new ObjectSerializer())
                .addSerializer(new ListSerializer())
                .addSerializer(new MapSerializer());


        HazelcastInstance hazelcastInstance = Hazelcast.getOrCreateHazelcastInstance(config);
        getLogger().info("HazelcastInstance  created... ");
        return hazelcastInstance;
    }

    @Bean
    public AlfrescoIntegration alfrescoIntegration() throws Exception {
        String app="/alfresco";
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(ContextLoader.getCurrentWebApplicationContext().getServletContext());
        SpringContextHolder.setApplicationContext(app,webApplicationContext);
        AlfrescoIntegration bean = SpringContextHolder.getApplicationContext(app).getBean(AlfrescoIntegration.class);
        getLogger().info(":::::::::::::AlfrescoIntegration "+(bean!=null?"registrado satisfactoriamente":" no registrado porque es null")+"::::::::::::::::::::::::::::::::::::::::::::");
       if(bean!=null)
           ServiceLocator.registerAlfrescoIntegration(bean);
        return bean;
    }

    @Bean(name = "clientRegistrationRepository")
    @Primary
    public ClientRegistrationRepository clientRegistrationRepository() {
        getLogger().info("Inicializando instancia de ClientRegistrationRepository para Wso2....");
        Wso2SecurityConfig conf=AuthenticationStore.getInstance().getWso2SecurityConfig();
        if(conf==null) {
            conf = Wso2SecurityConfig.create();
            if (!conf.isLoaded())
                conf.loadProperties();
            AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
        }
        getLogger().info(":::::::::::::::::::::::::::::::::::::::::::::::::::::::Construyendo ClientRegistrationRepository::::::::::::::::::::::::::::::::::::::::::::");
        clientId=conf.getClientId();
        clientSecret=conf.getClientSecret();
        issuerUri=conf.getIssuerUri();
        scope=conf.getScope();
        authorizationUri=conf.getAuthorizationUri();
        tokenUri=conf.getTokenUri();
        redirectUri=conf.getRedirectUri();
        authorizationGrantType=conf.getAuthorizationGrantType();
        clientAuthenticationMethod=conf.getClientAuthenticationMethod();
        jwkSetUri=conf.getJwkSetUri();
        userInfoUri=conf.getUserInfoUri();
       // ch.qos.logback.core.spi.Configurator conf;
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("wso2")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .issuerUri(issuerUri)
                .scope( scope.split(",\\s*|\\s+"))
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .redirectUri(redirectUri)
                .authorizationGrantType(new AuthorizationGrantType(authorizationGrantType))
                .clientAuthenticationMethod(getClientAuthenticationMethod(clientAuthenticationMethod))
                .jwkSetUri(jwkSetUri)
                .userInfoUri(userInfoUri)
                .build();
        getLogger().info(":::::::::::::::::::::::::::::::::::::::::::::::::::::::Construcción de ClientRegistrationRepository Finalizada!!!!::::::::::::::::::::::::::::::::::::::::::::");
        AuthenticationStore.getInstance().setClientRegistrationRepository(new InMemoryClientRegistrationRepository(clientRegistration));
        return AuthenticationStore.getInstance().getClientRegistrationRepository();
    }
    @Bean(name = "clientRegistrationRepository1")
    public ClientRegistrationRepository clientRegistrationRepository1(ClientRegistrationRepository clientRegistration) {
        getLogger().info(":::::::::::::::::::::::::::::::::::::::::::::::::::::::Construcción de ClientRegistrationRepository Finalizada!!!!::::::::::::::::::::::::::::::::::::::::::::");
        ClientRegistrationRepository repository= (ClientRegistrationRepository) Proxy.newProxyInstance(
                clientRegistration.getClass().getClassLoader(),
                new Class<?>[] { ClientRegistrationRepository.class },
                (proxy, method, args) -> {
                    if ("findByRegistrationId".equals(method.getName())) {
                        // Intercepta y modifica la llamada
                        if ("wso2".equals(args[0])) {
                            Wso2SecurityConfig conf=AuthenticationStore.getInstance().getWso2SecurityConfig();
                            if(conf==null) {
                                conf = Wso2SecurityConfig.create();
                                if (!conf.isLoaded())
                                    conf.loadProperties();
                                AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
                            }
                            clientId=conf.getClientId();
                            clientSecret=conf.getClientSecret();
                            issuerUri=conf.getIssuerUri();
                            scope=conf.getScope();
                            authorizationUri=conf.getAuthorizationUri();
                            tokenUri=conf.getTokenUri();
                            redirectUri=conf.getRedirectUri();
                            authorizationGrantType=conf.getAuthorizationGrantType();
                            clientAuthenticationMethod=conf.getClientAuthenticationMethod();
                            jwkSetUri=conf.getJwkSetUri();
                            userInfoUri=conf.getUserInfoUri();
                            // ch.qos.logback.core.spi.Configurator conf;
                            return  ClientRegistration.withRegistrationId("wso2")
                                    .clientId(clientId)
                                    .clientSecret(clientSecret)
                                    .issuerUri(issuerUri)
                                    .scope( scope.split(",\\s*|\\s+"))
                                    .authorizationUri(authorizationUri)
                                    .tokenUri(tokenUri)
                                    .redirectUri(redirectUri)
                                    .authorizationGrantType(new AuthorizationGrantType(authorizationGrantType))
                                    .clientAuthenticationMethod(getClientAuthenticationMethod(clientAuthenticationMethod))
                                    .jwkSetUri(jwkSetUri)
                                    .userInfoUri(userInfoUri)
                                    .build();
                        }
                    }
                    return method.invoke(clientRegistration, args);
                });
           AuthenticationStore.getInstance().setClientRegistrationRepository(repository);
           return repository;
    }

    public static ClientAuthenticationMethod getClientAuthenticationMethod(String methodName) {
        if (methodName == null || methodName.isEmpty()) {
            throw new IllegalArgumentException("El método de autenticación no puede ser nulo o vacío.");
        }

        switch (methodName) {
            case "client_secret_basic": return  ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post": return ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "client_secret_jwt": return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "private_key_jwt": return ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "none": return ClientAuthenticationMethod.NONE;
            default: {
                throw new IllegalArgumentException("Método de autenticación no reconocido: " + methodName);
            }
        }
    }
    public Wso2SecurityConfig loadProperties(String configFilePath, OpenIDConfiguration defaultConfig) {
        if(!loaded) {
            try {
                // Cargar las propiedades desde el archivo .properties
                FileInputStream fis = new FileInputStream(configFilePath);
                properties.load(fis);

                // Usar valores del archivo de propiedades o valores predeterminados del JSON
                this.clientId = properties.getProperty(
                        "oauth2.client.registration.wso2.client-id"
                );

                this.clientSecret = properties.getProperty(
                        "oauth2.client.registration.wso2.client-secret"
                );

                this.issuerUri = properties.getProperty(
                        "oauth2.client.registration.wso2.issuer-uri",
                        "https://localhost:9444/oauth2/token"
                );

                this.scope = properties.getProperty(
                        "oauth2.client.registration.wso2.scope",
                        String.join(",", defaultConfig.getScopesSupported())
                ).replace(",", " ");//.replace(" ", "%20");

                this.redirectUri = properties.getProperty(
                        "oauth2.client.registration.wso2.redirect-uri",
                        defaultConfig.getEndSessionEndpoint()
                );

                this.authorizationGrantType = properties.getProperty(
                        "oauth2.client.registration.wso2.authorization-grant-type",
                        defaultConfig.getGrantTypesSupported().contains("authorization_code")
                                ? "authorization_code"
                                : "implicit"
                );

                this.clientAuthenticationMethod = properties.getProperty(
                        "oauth2.client.registration.wso2.client-authentication-method",
                        String.join(",", defaultConfig.getTokenEndpointAuthMethodsSupported())
                );

                this.responseType = properties.getProperty(
                        "oauth2.client.registration.wso2.responseType", "code"
                );

                this.loginHint = properties.getProperty(
                        "oauth2.client.registration.wso2.login-hint", ""
                );

                this.authorizationUri = properties.getProperty(
                        "oauth2.client.provider.wso2.authorization-uri",
                        defaultConfig.getAuthorizationEndpoint()
                );

                this.tokenUri = properties.getProperty(
                        "oauth2.client.provider.wso2.token-uri",
                        defaultConfig.getTokenEndpoint()
                );

                this.jwkSetUri = properties.getProperty(
                        "oauth2.client.provider.wso2.jwk-set-uri",
                        defaultConfig.getJwksUri()
                );

                this.userInfoUri = properties.getProperty(
                        "oauth2.client.provider.wso2.user-info-uri",
                        defaultConfig.getUserinfoEndpoint()
                );

                this.parUri = properties.getProperty(
                        "oauth2.client.provider.wso2.par-uri",
                        defaultConfig.getPushedAuthorizationRequestEndpoint()
                );

                this.parEnable = Boolean.parseBoolean(properties.getProperty(
                        "oauth2.client.provider.wso2.par-enabled",
                        String.valueOf(defaultConfig.isRequestParameterSupported())
                ));

                this.privateKeyPath = properties.getProperty(
                        "oauth2.client.registration.wso2.private-key",
                        "/path/to/default/private-key.pem" // Valor predeterminado si no está en el JSON
                );
                this.pkceFlow = properties.getProperty("oauth2.client.registration.wso2.pkce-flow", "false");
                this.instrospec = properties.getProperty("oauth2.client.provider.wso2.introspect", "https://ses-idp.entalla.cu:9444/oauth2/introspect");

                loaded = true;
            } catch (IOException e) {
                e.printStackTrace();  // Manejar errores adecuadamente
            }
            AuthenticationStore.getInstance().setWso2SecurityConfig(this);
        }
        return this;
    }

    public Wso2SecurityConfig loadProperties(){
        if(!loaded) {
            String catalinaBase = System.getenv("CATALINA_BASE");
            if (catalinaBase == null) {
                catalinaBase = "/media/datos/Instaladores/entalla/tomcat";
                System.setProperty("CATALINA_BASE", catalinaBase);
            }
            if (catalinaBase != null) {
                String alfrescoConfigPath = catalinaBase + "/shared/classes/alfresco-global.properties";
                getLogger().info("Cargando propiedades desde:" + alfrescoConfigPath);
                if (new File(alfrescoConfigPath).exists()) {
                    globalPropertyFile = alfrescoConfigPath;
                }
            } else {
                String alfrescoConfigPath = catalinaBase + "/shared/classes/alfresco-global.properties";
                getLogger().info("No se encuentra valor para la propiedad CATALINA_BASE en el contexto de wso2-oauth-cms-client.");
            }
            loadProperties(globalPropertyFile);
            loaded = true;
            AuthenticationStore.getInstance().setWso2SecurityConfig(this);
        }
        return this;
    }


    public Wso2SecurityConfig loadProperties(String configFilePath) {
        if(!loaded) {
            try {
                FileInputStream fis = new FileInputStream(configFilePath);
                properties.load(fis);
                this.issuerUri = properties.getProperty(
                        "oauth2.client.registration.wso2.issuer-uri",
                        "https://localhost:9444/oauth2/token"
                );
                ConnectionChecker.ConnectionResult result = ConnectionChecker.getConnectionResult(this.issuerUri + "/.well-known/openid-configuration");
                if (result.isOk())
                    loadProperties(configFilePath, OpenIDConfiguration.loadFromJson(result.getResponse().toString()));
                else {
                    // Acceder a las propiedades específicas del archivo
                    // Asignar valores a los atributos de la clase desde el archivo de propiedades

                    this.scope = properties.getProperty("oauth2.client.registration.wso2.scope").replace(",", " ");//.replace(" ","%20");
                    this.redirectUri = properties.getProperty("oauth2.client.registration.wso2.redirect-uri");
                    this.authorizationGrantType = properties.getProperty("oauth2.client.registration.wso2.authorization-grant-type");
                    this.clientAuthenticationMethod = properties.getProperty("oauth2.client.registration.wso2.client-authentication-method");
                    this.authorizationUri = properties.getProperty("oauth2.client.provider.wso2.authorization-uri", "uri=https://ses-idp.entalla.cu:9444/oauth2/authorize");
                    this.tokenUri = properties.getProperty("oauth2.client.provider.wso2.token-uri", "https://ses-idp.entalla.cu:9444/oauth2/token");
                    this.jwkSetUri = properties.getProperty("oauth2.client.provider.wso2.jwk-set-uri", "https://ses-idp.entalla.cu:9444/oauth2/jwks");
                    this.userInfoUri = properties.getProperty("oauth2.client.provider.wso2.user-info-uri", "https://ses-idp.entalla.cu:9444/oauth2/userinfo");
                    this.parUri = properties.getProperty("oauth2.client.provider.wso2.par-uri");
                    this.responseType = properties.getProperty("oauth2.client.registration.wso2.responseType", "code");
                    this.loginHint = properties.getProperty("oauth2.client.registration.wso2.login-hint", "");
                    this.instrospec = properties.getProperty("oauth2.client.provider.wso2.introspect", "https://ses-idp.entalla.cu:9444/oauth2/introspect");
                }
                this.pkceFlow = properties.getProperty("oauth2.client.registration.wso2.pkce-flow", "false");
                this.clientId = properties.getProperty("oauth2.client.registration.wso2.client-id");
                this.clientSecret = properties.getProperty("oauth2.client.registration.wso2.client-secret");
                this.privateKeyPath = properties.getProperty("oauth2.client.registration.wso2.private-key", "");
                this.parEnable = properties.getProperty("oauth2.client.provider.wso2.par-enabled", this.parEnable ? "true" : "false") == "true";
                // Asignar a los campos de la clase
            } catch (IOException e) {
                e.printStackTrace();  // Manejar errores adecuadamente
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            loaded = true;
            AuthenticationStore.getInstance().setWso2SecurityConfig(this);
        }
        return this;
    }
    public String getPropertyByKey(String key,String defaultValue){
        if(properties.containsKey(key))
            return properties.getProperty(key,defaultValue);
        return defaultValue;
    }
    public String getPropertyByKey(String key){
        if(properties.containsKey(key))
            return properties.getProperty(key,null);
        return null;
    }
    public boolean getParEnable() {
        return parEnable;
    }
    public String getParUri() {
        return parUri;
    }

    public Properties getProperties() {
        return properties;
    }

    public String getGlobalPropertyFile() {
        return globalPropertyFile;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getScope() {
        return scope;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public String getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public String getUserInfoUri() {
        return userInfoUri;
    }

    public String generateCodeVerifier(){
        return new PKCEUtil().generateCodeVerifier();
    }
    public String generateCodeChallenge(String codeVerifier){
        return new PKCEUtil().generateCodeChallenge(codeVerifier);
    }

    public String extractBaseURL(String urlString) throws MalformedURLException {

        // Crear un objeto URL
        URL url = new URL(urlString);

        // Obtener el protocolo (http o https)
        String protocol = url.getProtocol();

        // Obtener el host (ses-cms.entalla.cu)
        String host = url.getHost();

        // Obtener el puerto si está definido, de lo contrario será -1
        int port = url.getPort();

        // Construir la base URL
        StringBuilder baseUrl = new StringBuilder();
        baseUrl.append(protocol).append("://").append(host);

        // Agregar el puerto si está definido
        if (port != -1) {
            baseUrl.append(":").append(port);
        }

        return baseUrl.toString();
    }

    public boolean isPkceFlow() {
        return pkceFlow!=null && pkceFlow.toLowerCase()=="true";
    }

}

final class PKCEUtil {

    public String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new Random().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
