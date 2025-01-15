package cu.entalla.config;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.claim.validator.CustomJwtClaimValidator;
import cu.entalla.client.ConnectionChecker;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.loader.KeyLoader;
import cu.entalla.loader.LocalJWKSetLoader;
import cu.entalla.model.JwkKey;
import cu.entalla.model.JwtAlgorithmConfig;
import cu.entalla.model.OpenIDConfiguration;
import cu.entalla.security.client.oauth2.OAuth2CallbackServlet;
import cu.entalla.serializer.*;
import cu.entalla.service.AuthenticationService;
import cu.entalla.service.ServiceLocator;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.udi.ClientServiceIntegration;
import cu.entalla.util.ClassLoaderUtil;
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
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.jwt.*;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Collectors;


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
    private String parEnable="true";

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

    private String sessionState;

    private static final Logger logger = Logger.getLogger(Wso2SecurityConfig.class.getName());
   
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
        logger.info("----------------------------Creando instancia de Wso2SecurityConfig----------------------------");
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
            logger.info("---------------------------- Cargando propiedades de Wso2SecurityConfig desde:"+catalinaBase+" ----------------------------");
            getLogger().info("CATALINA_BASE ON OAuth2CallbackServlet="+catalinaBase);
            catalinaBase+=(catalinaBase.endsWith("/")?"":"/");
            String configFilePath = catalinaBase + "shared/classes/alfresco-global.properties";
            getLogger().info("WSO2_CONFIG_FILE="+configFilePath);
            AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecurityConfig);
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFilePath);
            AuthenticationService authService=new AuthenticationService(client);
            logger.info("----------------------------Instancia de Wso2SecurityConfig creada----------------------------");

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

    @Bean(name="hazelcastInstance")
    public HazelcastInstance hazelcastInstance(){

        logger.info("----------------------------Creando instancia de HazelCast----------------------------");
        Wso2SecurityConfig conf=AuthenticationStore.getInstance().getWso2SecurityConfig();

        if(conf==null) {
            conf = Wso2SecurityConfig.create();
            if (!conf.isLoaded())
                conf.loadProperties();
            AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
        }
        boolean enabled=conf.getPropertyByKey("hazelcast.instance.enabled","")=="true";
        if(!enabled) return null;
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


        HazelcastInstance instance = Hazelcast.getOrCreateHazelcastInstance(config);
        getLogger().info("HazelcastInstance  created... ");
        return instance;
    }

    @Bean(name="jwtProcessor")
    public ConfigurableJWTProcessor<SecurityContext> jwtProcessor() throws MalformedURLException {
        // Crear el procesador JWT base
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // URL donde se encuentra el JWK Set
        String jwkSetUri = getJwkSetUri();

        // Configurar un JWK source
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwkSetUri));

        // Configurar el selector JWE para descifrado
        JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128CBC_HS256,
                jwkSource
        );

        // Configurar el selector JWS para verificación de firma
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                jwkSource
        );

        // Asignar ambos selectores al procesador JWT
        jwtProcessor.setJWEKeySelector(jweKeySelector); // Añadir JWE selector
        jwtProcessor.setJWSKeySelector(jwsKeySelector); // Añadir JWS selector
         return jwtProcessor;
    }
    @Bean(name="customJwtClaimValidator")
    public CustomJwtClaimValidator customJwtClaimValidator() {
        // Ejemplo: Validar si el claim "aud" tiene un valor específico
        return new CustomJwtClaimValidator("aud", value -> value.equals(this.clientId));
    }
    @Bean(name="delegatingOAuth2TokenValidator")
    public DelegatingOAuth2TokenValidator<Jwt> delegatingOAuth2TokenValidator(
            CustomJwtClaimValidator customJwtClaimValidator) {
        // Validadores existentes
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
        JwtClaimValidator<String> audienceValidator = new JwtClaimValidator<>(
                "aud", audience -> audience != null && audience.equals(this.clientId)
        );
        JwtClaimValidator<String> issuerValidator = new JwtClaimValidator<>(
                "iss", issuer -> issuer != null && issuer.equals(this.issuerUri)
        );

        // Combina todos los validadores, incluyendo el custom
        return new DelegatingOAuth2TokenValidator<>(
                timestampValidator, audienceValidator, issuerValidator, customJwtClaimValidator
        );
    }


    @Bean(name="jwtDecoder")
    public org.springframework.security.oauth2.jwt.JwtDecoder jwtDecoder() throws MalformedURLException {
        logger.info("----------------------------Creando instancia de JwtDecoder----------------------------");

        ConfigurableJWTProcessor<SecurityContext> securityContextConfigurableJWTProcessor = jwtProcessor();

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(securityContextConfigurableJWTProcessor);

        // Agregar validadores de claims y token
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
        JwtClaimValidator<String> audienceValidator = new JwtClaimValidator<>(
                "aud", audience -> audience != null && audience.equals(this.clientId)
        );
        JwtClaimValidator<String> issuerValidator = new JwtClaimValidator<>(
                "iss", issuer -> issuer != null && issuer.equals(this.issuerUri)
        );
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(timestampValidator, audienceValidator, issuerValidator);

        jwtDecoder.setJwtValidator(combinedValidator);

        logger.info("----------------------------Instancia de JwtDecoder creada----------------------------");
        return jwtDecoder;
    }

    @Bean(name="createCustomJwtDecoder")
    public org.springframework.security.oauth2.jwt.JwtDecoder createCustomJwtDecoder(JWEAlgorithm jweAlgorithm,EncryptionMethod encryptionMethod,JWSAlgorithm jwsAlgorithm) throws MalformedURLException {
        logger.info("----------------------------Creando instancia de JwtDecoder----------------------------");

        // Crear el procesador JWT base
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // URL donde se encuentra el JWK Set
        String jwkSetUri = getJwkSetUri();

        // Configurar un JWK source
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwkSetUri));

        if(jweAlgorithm!=null  && encryptionMethod!=null){
            // Configurar el selector JWE para descifrado
            JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                    jweAlgorithm,
                    encryptionMethod,
                    jwkSource
            );
           jwtProcessor.setJWEKeySelector(jweKeySelector); // Añadir JWE selector
        }
        if(jwsAlgorithm!=null){
            // Configurar el selector JWS para verificación de firma
            JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
                    jwsAlgorithm,
                    jwkSource
            );
            jwtProcessor.setJWSKeySelector(jwsKeySelector); // Añadir JWS selector
        }

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        // Agregar validadores de claims y token
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
        JwtClaimValidator<String> audienceValidator = new JwtClaimValidator<>(
                "aud", audience -> audience != null && audience.equals(this.clientId)
        );
        JwtClaimValidator<String> issuerValidator = new JwtClaimValidator<>(
                "iss", issuer -> issuer != null && issuer.equals(this.issuerUri)
        );
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(timestampValidator, audienceValidator, issuerValidator);
        jwtDecoder.setJwtValidator(combinedValidator);
        logger.info("----------------------------Instancia de JwtDecoder creada----------------------------");
        return jwtDecoder;
    }
    @Bean(name="createJwtDecoderFromJwksUrlService")
    public org.springframework.security.oauth2.jwt.JwtDecoder createJwtDecoderFromJwksUrlService( ) throws Exception {
        logger.info("----------------------------Creando instancia de JwtDecoder----------------------------");

        List<JwtAlgorithmConfig> jwkAlgorithmConfigFromUri = getJwkAlgorithmConfigFromUri(jwkSetUri);
        JwtAlgorithmConfig conf=jwkAlgorithmConfigFromUri.get(0);
        // Crear el procesador JWT base
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // URL donde se encuentra el JWK Set
        String jwkSetUri = getJwkSetUri();

        // Configurar un JWK source
        JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(jwkSetUri));

        if(conf.getJweAlgorithm()!=null && conf.getEncryptionMethod()!=null){
            // Configurar el selector JWE para descifrado
            JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                    conf.getJweAlgorithm(),
                    conf.getEncryptionMethod(),
                    jwkSource
            );
            jwtProcessor.setJWEKeySelector(jweKeySelector); // Añadir JWE selector
        }
        if( conf.getJwsAlgorithm()!=null){
            // Configurar el selector JWS para verificación de firma
            JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
                    conf.getJwsAlgorithm(),
                    jwkSource
            );
            jwtProcessor.setJWSKeySelector(jwsKeySelector); // Añadir JWS selector
        }

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);

        // Agregar validadores de claims y token
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
        JwtClaimValidator<String> audienceValidator = new JwtClaimValidator<>(
                "aud", audience -> audience != null && audience.equals(this.clientId)
        );
        JwtClaimValidator<String> issuerValidator = new JwtClaimValidator<>(
                "iss", issuer -> issuer != null && issuer.equals(this.issuerUri)
        );
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(timestampValidator, audienceValidator, issuerValidator);

        jwtDecoder.setJwtValidator(combinedValidator);

        logger.info("----------------------------Instancia de JwtDecoder creada----------------------------");
        return jwtDecoder;
    }

    @Bean(name="createJwtDecoderFromJwksUrl")
    public org.springframework.security.oauth2.jwt.JwtDecoder createJwtDecoderFromJwksUrl() throws Exception {
         return createJwtDecoderFromJwksUrlService();
    }

    @Bean
    public JwtDecoder jwtLocalDecoder() throws Exception {
        JwtConfig jwtConfig = new JwtConfig();
        // Cargar clave privada desde un archivo PEM
        //PrivateKey privateKey = jwtConfig.loadPrivateKey();

        // Crear un procesador JWT
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        // Configurar un JWK source
        JWKSource<SecurityContext> jwkPrivateSource =getJwkPrivateSource();

        JWKSource<SecurityContext> jwkPublicSource=getJwkPublicSource();

        // Configurar el descifrador JWE (Encrypted JWT)
        JWEDecryptionKeySelector<SecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, jwkPrivateSource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        JWSVerificationKeySelector<SecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkPublicSource);
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        return new NimbusJwtDecoder(jwtProcessor);
    }
    public JWKSource<SecurityContext> getJwkPublicSource(){
        JwtConfig jwtConfig = new JwtConfig();
        return new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return getJWKSet(securityContext).getKeys();
            }
            public JWKSet getJWKSet(SecurityContext context)  {
                try {
                    return new LocalJWKSetLoader().loadJWKSetFromFile(jwtConfig.getPublicKeyPath());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
    @Bean
    public JWKSource<SecurityContext> getJwkPrivateSource(){
        return new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return getJWKSet(securityContext).getKeys();
            }
            public JWKSet getJWKSet(SecurityContext context)  {
                try {
                    return new LocalJWKSetLoader().loadJWKSetFromFile(privateKeyPath);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
    public byte[] getPublicKeyBytes() throws Exception {
        // Lee el contenido de un archivo PEM
        return Files.readAllBytes(Paths.get(new JwtConfig().getPublicKeyPath()));
    }
    public String getPublicKeyBase64() {
        try {
            RSAPublicKey publicKey = ConnectionChecker.getPublicKeyFromJWKS(this.jwkSetUri);
            // Obtener los bytes de la clave pública en formato X.509
            byte[] encodedPublicKey = publicKey.getEncoded();
            // Convertir los bytes a Base64
            return Base64.getEncoder().encodeToString(encodedPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey getPublicKeyFromJWKS() {
        try {
            return ConnectionChecker.getPublicKeyFromJWKS(this.jwkSetUri);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    @Bean(name = "privateKeyPath")
    public String getPrivateKeyPath(){
        JwtConfig jwtConfig = new JwtConfig();
        return jwtConfig.getPrivateKeyPath();
    }

    public String getPublicKeyPath(){
        JwtConfig jwtConfig = new JwtConfig();
        return jwtConfig.getPublicKeyPath();
    }

    public java.security.spec.PKCS8EncodedKeySpec getPKCS8EncodedKeySpec() throws IOException {
        String privateKeyPath1 = getPrivateKeyPath();
        logger.info("::::::::::::::::::::::::::::::::::::: Se comienza la lectura de la llave privada para construir instancia de PKCS8EncodedKeySpec :::::::::::::::::::::::::::::::::::");

        PrivateKey privateKey = KeyLoader.loadPrivateKey(privateKeyPath1);

        logger.info(":::::::::::: Private Key loaded successfully ::::::::::::");
        // Decodificar la cadena Base64 a un arreglo de bytes
        byte[] decodedKey = privateKey.getEncoded();
        // Crear un objeto PKCS8EncodedKeySpec
        return new PKCS8EncodedKeySpec(decodedKey);
    }

    public PublicKey getPublicKey() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPath1 = getPublicKeyPath();
        logger.info("::::::::::::::::::::::::::::::::::::: Se comienza la lectura de la llave pública  :::::::::::::::::::::::::::::::::::");
        return  KeyLoader.getPublicKey(publicKeyPath1);
    }
    public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPath1 = getPrivateKeyPath();
        logger.info("::::::::::::::::::::::::::::::::::::: Se comienza la lectura de la llave privada :::::::::::::::::::::::::::::::::::");
        return  KeyLoader.getPrivateKey(privateKeyPath1);
    }

    /**
     * Obtiene el KeyId necesario para otros procesos.
     *
     * @return El KeyId dinámico.
     */
    @Bean(name="KeyId")
    public String getKeyId() throws Exception {
        List<JwkKey> jwkKeysFromJWKS = ConnectionChecker.getJwkKeysFromJWKS(jwkSetUri);
        // Aquí puedes obtener el keyId de una fuente dinámica, como propiedades o un cálculo
        return !jwkKeysFromJWKS.isEmpty()?jwkKeysFromJWKS.get(0).getKeyId():null;
    }

    public List<JwkKey> getJwkKeysFromUri() throws Exception {
        List<JwkKey> jwkKeysFromJWKS = ConnectionChecker.getJwkKeysFromJWKS(jwkSetUri);
        // Aquí puedes obtener el keyId de una fuente dinámica, como propiedades o un cálculo
        return !jwkKeysFromJWKS.isEmpty()?jwkKeysFromJWKS:null;
    }
    public List<JwkKey> getJwkKeysFromUri(String jwkSetUri) throws Exception {
        List<JwkKey> jwkKeysFromJWKS = ConnectionChecker.getJwkKeysFromJWKS(jwkSetUri);
        // Aquí puedes obtener el keyId de una fuente dinámica, como propiedades o un cálculo
        return !jwkKeysFromJWKS.isEmpty()?jwkKeysFromJWKS:null;
    }
    public List<JwtAlgorithmConfig> getJwkAlgorithmConfigFromUri(String jwkSetUri) throws Exception {
        AtomicInteger count= new AtomicInteger();
        List<JwtAlgorithmConfig> jwkKeysFromJWKS = ConnectionChecker.getJwkKeysFromJWKS(jwkSetUri).stream().map((el)->{
            return el.toJwtAlgorithmConfig();
        }).collect(Collectors.toList());
        // Aquí puedes obtener el keyId de una fuente dinámica, como propiedades o un cálculo
        return !jwkKeysFromJWKS.isEmpty()?jwkKeysFromJWKS:null;
    }

    @Bean(name="getIntegrator")
    public ClientServiceIntegration getIntegrator() throws Exception {
        String app="/alfresco";
        WebApplicationContext currentWebApplicationContext = ContextLoader.getCurrentWebApplicationContext();
        if(currentWebApplicationContext!=null) {
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(currentWebApplicationContext.getServletContext());
            app = currentWebApplicationContext.getServletContext().getContextPath();
            logger.info("----------------------------Creando instancia de ClientServiceIntegration en "+app+" con getIntegrator()----------------------------");
            String className = "cu.entalla.component.AlfrescoIntegratorImpl";
            SpringContextHolder.setApplicationContext(app, webApplicationContext);
            ClientServiceIntegration bean = ClassLoaderUtil.loadDynamicBean(SpringContextHolder.getApplicationContext(app), className,ClientServiceIntegration.class);
            logger.info(":::::::::::::ClientServiceIntegration " + (bean != null ? "registrado satisfactoriamente" : " no registrado porque es null") + "::::::::::::::::::::::::::::::::::::::::::::");
            if (bean != null)
                ServiceLocator.registerIntegrator(bean);
            return bean;
        }
        logger.info("----------------------------Instancia de ClientServiceIntegration is null----------------------------");
        return null;
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
                .userNameAttributeName("username")
                .providerConfigurationMetadata(Map.of(
                        "userinfo_endpoint", userInfoUri,
                        "additional_param", "value"
                ))
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

    public Wso2SecurityConfig initialize() throws Exception {
        logger.info("----------------------------Inicializando componentes desde Listener----------------------------");
        if(!isLoaded()) loadProperties();
        clientRegistrationRepository();
        getIntegrator();
        hazelcastInstance();
        logger.info("----------------------------Inicialización de componentes finalizada desde Listener----------------------------");
        return this;
    }
    public String getAuthenticatedUserKeyWord(){
        return isLoaded() && properties.containsKey("external.authentication.proxyHeader")?getPropertyByKey("external.authentication.proxyHeader","X-Alfresco-Remote-User"):"X-Alfresco-Remote-User";
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

                this.parEnable =  properties.getProperty(
                        "oauth2.client.provider.wso2.par-enabled",
                        "true"
                );

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
                String clientConfigPath = catalinaBase + "/shared/classes/alfresco-global.properties";
                getLogger().info("Cargando propiedades desde:" + clientConfigPath);
                if (new File(clientConfigPath).exists()) {
                    globalPropertyFile = clientConfigPath;
                }
            } else {
                String clientConfigPath = catalinaBase + "/shared/classes/alfresco-global.properties";
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
                        "oauth2.client.provider.wso2.issuer-uri",
                        "https://localhost:9444/oauth2/token"
                );
                ConnectionChecker.ConnectionResult result = ConnectionChecker.getConnectionResult(this.issuerUri + "/.well-known/openid-configuration");
                if (result!= null && result.isOk())
                    loadProperties(configFilePath, OpenIDConfiguration.loadFromJson(result.getResponse().toString()));
                else if(result==null || result!=null && !result.isOk()){
                    loadProperties();
                }
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
                this.parEnable = properties.getProperty("oauth2.client.provider.wso2.par-enabled", "false") ;
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
        return "true".equals(parEnable);
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


    public void cleanup() {

    }
    public static void main(String[] args) {
        try {
            String accessToken="access_token=eyJ4NXQiOiJZVEpsTTJabE56RXlZbU5rTXpsbE1ERmtNbVE0WWpRek9EVTBOVFZpWm1NeU1qUXhaREV3WWpZeU5qazFNalpqT0dSa01XTmxPVEEwWkdRellUQTNOdyIsImtpZCI6IllUSmxNMlpsTnpFeVltTmtNemxsTURGa01tUTRZalF6T0RVME5UVmlabU15TWpReFpERXdZall5TmprMU1qWmpPR1JrTVdObE9UQTBaR1F6WVRBM053X1JTMjU2IiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI4MGYwMGI1Yy0wYmEyLTQ1NzItOTU3YS1hOTY3ODI5OTlmMDYiLCJhdXQiOiJBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoic3NvLXNlc3Npb24iLCJpc3MiOiJodHRwczpcL1wvc2VzLWlkcC5lbnRhbGxhLmN1Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJnaXZlbl9uYW1lIjoiUGVyc3kiLCJjbGllbnRfaWQiOiJGQTZVQW9iZDJFeFkyaHVhZzVDSUJhendHWjBhIiwiYXVkIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm5iZiI6MTczNjgzMzc5MiwiYXpwIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm9yZ19pZCI6IjEwMDg0YThkLTExM2YtNDIxMS1hMGQ1LWVmZTM2YjA4MjIxMSIsInNjb3BlIjoiZW1haWwgb3BlbmlkIHBob25lIHByb2ZpbGUiLCJwaG9uZV9udW1iZXIiOiIrNTMgNTMzNjQ2NTQiLCJleHAiOjE3MzY4MzczOTIsIm9yZ19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MzY4MzM3OTIsImZhbWlseV9uYW1lIjoiTW9yZWxsIEd1ZXJyYSIsImJpbmRpbmdfcmVmIjoiM2NhZDI1ZGY2ODk4N2Y0ODA0NWUwODdjNGQwMDc0YTYiLCJqdGkiOiJjYTkxMGU1ZC0yMDVlLTRjZjctOTgxZC1lMjRmMTgwZGJjYmEiLCJlbWFpbCI6InBtb3JlbGxAeGV0aWQuY3UiLCJ1c2VybmFtZSI6ImFkbWluIn0.MylUFgiIVbTE6j12lXJs4hxvmoPMbNNlBASkRIiLWFvOlv0KNg1rhOFBCn8MP_BnGYf2PRUwnEd61IHLaGrfPPjePz2mB2tjgVMmUNEtyoQ3yn8OYqtazhdV1MFmQoCMzT-9v8w84BI3zUMEeAv2tVVPAr26wmJLy1yeCDrInF9le2mU8w0oQopTnCIvs38XkyG_84WyxOOaH9JrYSCMvX3B47pqAGDnnmMcjYNvAnCnzCD1xHQ82T9a_fMGGaijmEgNsTRfBwaihmAT1zsBAWtU8jpH3JPIHdT9Hq41AnjPct2i_0zOIgFIn8XpCgY3duaPWcbpGe7FJXJHIk-TzQ.eyJzdWIiOiI4MGYwMGI1Yy0wYmEyLTQ1NzItOTU3YS1hOTY3ODI5OTlmMDYiLCJhdXQiOiJBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoic3NvLXNlc3Npb24iLCJpc3MiOiJodHRwczpcL1wvc2VzLWlkcC5lbnRhbGxhLmN1Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJnaXZlbl9uYW1lIjoiUGVyc3kiLCJjbGllbnRfaWQiOiJGQTZVQW9iZDJFeFkyaHVhZzVDSUJhendHWjBhIiwiYXVkIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm5iZiI6MTczNjc5OTEwOSwiYXpwIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm9yZ19pZCI6IjEwMDg0YThkLTExM2YtNDIxMS1hMGQ1LWVmZTM2YjA4MjIxMSIsInNjb3BlIjoiZW1haWwgb3BlbmlkIHBob25lIHByb2ZpbGUiLCJwaG9uZV9udW1iZXIiOiIrNTMgNTMzNjQ2NTQiLCJleHAiOjE3MzY4MDI3MDksIm9yZ19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MzY3OTkxMDksImZhbWlseV9uYW1lIjoiTW9yZWxsIEd1ZXJyYSIsImJpbmRpbmdfcmVmIjoiOTY1MDQwYTAwMTdmNGZiMGZiMWNiNzMyODU2ZmY5OWMiLCJqdGkiOiIyY2QyZGM4Zi1iZWQxLTQ1YTgtOGY3NC02MGM3MTY2MjhiMmQiLCJlbWFpbCI6InBtb3JlbGxAeGV0aWQuY3UiLCJ1c2VybmFtZSI6ImFkbWluIn0.bEEEzE9hpnINB7BUch85MAxOxFZQ6CELVhoRAmEtuw7Yns7w43R3x8SoSeK6mZPTKwxMaC9exm7fuWpb21hyFstM3qtQE3zk1Q75BfwcTrGebC0BPKWqAXEWwoBAUYFCaT-cC6-TdB1uFvA7Xn1XyBPNBznNVdg0CnhL-GgOV7bUSj08HasigCFppZCBZao6AJxIdyeoNplz4jTttdBhD_T7ufjj-fVTZW2Y2RR6gEoL6MO967AP1QRtDQy2oC4NT7pnVa9r0Oub8bAnjenDoYtlQA2ZkOOATexb_ryqVys40u3aTSdK34zvdebAD-Uqs3Em6jxxeFR1Qt-ewA-YLA.eyJzdWIiOiI4MGYwMGI1Yy0wYmEyLTQ1NzItOTU3YS1hOTY3ODI5OTlmMDYiLCJhdXQiOiJBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoic3NvLXNlc3Npb24iLCJpc3MiOiJodHRwczpcL1wvc2VzLWlkcC5lbnRhbGxhLmN1Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJnaXZlbl9uYW1lIjoiUGVyc3kiLCJjbGllbnRfaWQiOiJGQTZVQW9iZDJFeFkyaHVhZzVDSUJhendHWjBhIiwiYXVkIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm5iZiI6MTczNjc5MDg2NSwiYXpwIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm9yZ19pZCI6IjEwMDg0YThkLTExM2YtNDIxMS1hMGQ1LWVmZTM2YjA4MjIxMSIsInNjb3BlIjoiZW1haWwgb3BlbmlkIHBob25lIHByb2ZpbGUiLCJwaG9uZV9udW1iZXIiOiIrNTMgNTMzNjQ2NTQiLCJleHAiOjE3MzY3OTQ0NjUsIm9yZ19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MzY3OTA4NjUsImZhbWlseV9uYW1lIjoiTW9yZWxsIEd1ZXJyYSIsImJpbmRpbmdfcmVmIjoiMDcwN2QzOGJiOTllYTkwM2RiYzNmYWFmYzZiMjQ0YzYiLCJqdGkiOiIyMDRmODM0Ny05YWFlLTRkZmUtYWQ1YS02ODg4MzY3MGE1MTQiLCJlbWFpbCI6InBtb3JlbGxAeGV0aWQuY3UiLCJ1c2VybmFtZSI6ImFkbWluIn0.sBMmFZcZp59xj5r1kszgPzVeuFH_pPyga9_J5mW0iyxgxViPKxL4NLm3eueJODywcHegkkQXpGrlYLoxkocTxjrl2WEs3SNEl_-Utwm8ie-eSKZQgR2_oAjP5NZrByG_FRul77uwk5gdB_wXG1r2fUI-t19k3G7UfliDKW_WX9nmL1-MNSkrZ3CtGmb__yLtZvso1zWwvp-yRz4sxB-YSb0ownVrKjayaeUKV9-LCDeO7uUb5v4iMUT21Hh5jHeqeGKTiwijqbdme0y-xaV8I16hhim5JuMzI3OKgiBSik1FkUpJHExRrVCbSnwmdVEr2T9Anh9TcbzRFGrC4g_GhA.M8Zfs5Cwwpad2MqgP8gkH_ZOE6zmPA7J5J5bw65aju4Bs4OMMWDdCgViFEQvJ2F95qFyQOxaHmxPn4l9g9JTB3rjth_cHBZjTbYujaum0LbRz7K9IwRvvLgBTo-h2QNyXGO7mlZtgXkNlg3eHucXM8Pe6WF646wGNW2S0Ua5B8PchzuRz_Xt3A0MIxy6XYwIHbht8ae7K2dAz_AZw88m2m3MRhHQ-G8g1kETfat5JEy_hzRHGKHaXIosYa4165D_GnqUiD9FNkf5R-i5tBpSUurbnWNmIazjN3QwlaLLJC7XUi7soBmVBXevnA2GrHaa7N-ji4zBtna_2suPJsjYmw.rGEGtMOhaYeBioZQ.A1Z1n_sYmb05iZNC3oyoSOfNbZGV60d5qxi1V-CBbBO-3z8DLeYx51CrIme28DrJF31QUdd_4uMstdITEsiNssROaQrxj41RwJvZT1t0p-xgV-Xpez2ByVK4uNlU6TcZKjtpeDsoh8i7Q4dQV2WMO2SiNaCKrSctZgzbi8wC-OjzJFnBcaUgJJH7qmPPfvxkYSvt4tRm7-ld-cHyUfqZbPg7G9H8gafjVlF7bpzCz9RDEHr6WzOS0M0r_Et3hMF74aUoa9k-ryyaX1Co6kqt6uWdXKSp_64n1RYjNCqsQY3Egu65b0SXeTm9eptpslUjYSDLYMOBBk-JaoRWFaC_k61rmhPz1djQKxLQ-XfNE22r1AEXTT0jULzA8Vh9UmbKRrt7XpmDM5QUC5_SOAKTmaNuqBW0muCK8RdxqhVlFN68X2yJZq6XKE8cvxlSVYnTxg9gq9KJ_veUOFs6rbE3SDyqOSe9PSVJ2xHberqMZ_-P_OpR8NEGCwccgqi1Qv47mI0HdKA_V7_wNb4lhNCRrH5Rq-J8fssaD7gSIIR5iSKYvX_u-Oo8bWObJu-KthCulsbNf7kEtRzsYv6uhzgfMUtc7WajFHqRSLCn7SjJyMt2TIBzSECAIQyHhnlkhpaMMffF7V8gni6sKahYfnVnM8gBJPdshzL4DXs1KiWSYKWfi5ZOtzcKd-xpUD9UxOmU8AqixLIsNNDevRYRNl78KJACQP0YsUnWCvInng6QVJlsgQPTQR1IuzIls5KVjoeOorDncvfBMdE5CvL6CXW_6DLeYotbAvDRarojDao4gGGuvfAIqj7DHxEBfepZt3tLTu5DpgqOEk1QPC_oSzpwA_jqR3kDLbZ93qHhUC-VfXrBmzY7Ijxk7dV41cRLTBZr33oL5X69opHJbdEqO2ZJswg4CAXO8-7Kz9rdiSLxfYYXTgOqVILeEcvi7byjXdzjFkH3dAf8FAwwWJdxkpOoPKeJ7wUumR9wi0Vh6dlTYRl9oJbCpcyk33gq4X1sAPPEzOo13bUM_1f7PWl-7rM8mGdblvhJz4sABhrYRcDPNLg0JhZ_xXime4F222YhN1S6-WcpXOOBJxDsSvYP5qgNXiPZoolAqKjH9BHH5VVSJmQaBmmqG4a3yGdQYIyLlDMhkcZxuYEgRBAis_TSGfppXXFQ_Fp6EUf-TPAFzLna2LbM97TmIGRgjzw9mJYeZZIesx6-RDrCcDAL_4mqNBRoXPABW6UMNp2-MK0xKy_LN9P04prGoBahk_sgmMGU6zlfewwxV24I-aHOAcAeOeOBpKTyj6o8V8dKyRUaLOqxgquTwRyqA-8fXyn3O6rKuHZw790SskPaewAHi16yhdXIfAro_7x1cEfT7SgIeuPHnI8bUUY7XGgGl3y3JrsuPJveGfIGT1Qthd5OFdaimNJ8u_hAvyVVdRUH7pbta9fdjWHoI60GN8sH0NWMBWwrCNlkiBGST4H_ULjm5HLDLuorXyKYwYhf0U7CxfkVyIOWuGA5nk5p9XcT801iIm0rPy5rM_wKSBwzM7wI7rQO0FldP3EF-4NJI20_L_WV5wSGaWFcKV0u18MIzj8mG0CAFFPhRlzPgn9-isbWYCT5bEDXDO99TQDzrqUcndBkrt5mb18iMnyI4aQ5z7B9BL6NHa1MLtGKd3ngrAzH1ESWww5DI-sO9CPOdBPsHGF3bJlq1ynPzxU5yfAjmd4zR4nP09-hK-v5UgGaHhBei24-VQUkZz6pzFtA3WEP06YytmGk4hxwB5IILOUE2Bj6myRWILxTZlaPVNVyP3bRdV0M_BnyhdeN40jzecSRD6ZsVvoUFJhYEfn3FmwgWdan1Bj9I8ldaFvvARJ9K84iNVHqToMBamYugf664KojeLLOglk6zAvUCVPqgD4d7e7_-saMY-OqjChAySxXi9PrEAsidKjhKK7lf7IBUUmyWFILbwoLPkhmXxcn4lZX8q_u9nKmkVumiEBtvsYtcMafjD3Z5yt7FKSEvWKefEDkQq7PtIDa9So-uJZxvpF8KgcQ1b44djku7A.6qicVji8rAKNK71m8JZaYg";
            Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create();
            AuthenticationService authService=new AuthenticationService();
            authService.isValidToken(accessToken);
            System.out.println("wso2".getClass());

        } catch (Exception e) {
            e.printStackTrace();
        }
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
