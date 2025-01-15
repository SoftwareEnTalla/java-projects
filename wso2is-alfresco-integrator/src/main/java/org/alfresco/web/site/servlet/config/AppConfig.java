//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.store.AuthenticationStore;
import net.minidev.json.JSONObject;
import org.alfresco.web.site.TaskUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Configuration
public class AppConfig {
    private static final Log logger = LogFactory.getLog(AppConfig.class);
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private final String authUrl;
    private final String principalAttribute;


    private final AIMSConfig aimsConfig;
    private static final String REALMS = "realms";
    private static final RestTemplate rest = new RestTemplate();
    private static final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
    };
    private String  wellKnownOpenidConfigurationUrl;
    private String  issuerUri;

    @Autowired
    public AppConfig(AIMSConfig aimsConfig) {
        this.aimsConfig = aimsConfig;
        this.realm = aimsConfig.getRealm();
        this.clientId = aimsConfig.getResource();
        this.clientSecret = aimsConfig.getSecret();
        this.authUrl = aimsConfig.getAuthServerUrl();
        this.principalAttribute = aimsConfig.getPrincipalAttribute();
        this.wellKnownOpenidConfigurationUrl=aimsConfig.getWellKnownOpenidConfigurationUrl();
        this.issuerUri=aimsConfig.getIssuerUri();
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(@Autowired(required = false) OAuth2AuthorizedClientService authorizedClientService) {
        return null != authorizedClientService ? new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService) : null;
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(@Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository) {
        return null != clientRegistrationRepository ? new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository) : null;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() throws ParseException {
        ClientRegistration wso2ClientRegistration=this.getWso2ClientRegistration();
        ClientRegistration clientRegistration = this.clientRegistration();
        return null != clientRegistration ? new InMemoryClientRegistrationRepository(new ClientRegistration[]{wso2ClientRegistration,this.clientRegistration()}) : null;
    }

    @Bean
    public AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceAndManager(@Autowired(required = false) ClientRegistrationRepository clientRegistrationRepository, @Autowired(required = false) OAuth2AuthorizedClientService authorizedClientService) {
        if (null != clientRegistrationRepository && null != authorizedClientService) {
            OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode().build();
            AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
            authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
            return authorizedClientManager;
        } else {
            return null;
        }
    }
    private ClientRegistration getWso2ClientRegistration(){
        Wso2SecurityConfig conf=AuthenticationStore.getInstance().getWso2SecurityConfig();
        if(conf==null) {
            conf = Wso2SecurityConfig.create();
            if (!conf.isLoaded())
                conf.loadProperties();
            AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
        }
        logger.info(":::::::::::::::::::::::::Construyendo WSO2 ClientRegistrationRepository::::::::::::::::");

        // ch.qos.logback.core.spi.Configurator conf;
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("wso2")
                .clientId(conf.getClientId())
                .clientSecret(conf.getClientSecret())
                .issuerUri(conf.getIssuerUri())
                .scope( conf.getScope().split(",\\s*|\\s+"))
                .authorizationUri(conf.getAuthorizationUri())
                .tokenUri(conf.getTokenUri())
                .redirectUri(conf.getRedirectUri())
                .authorizationGrantType(new AuthorizationGrantType(conf.getAuthorizationGrantType()))
                .clientAuthenticationMethod(getClientAuthenticationMethod(conf.getClientAuthenticationMethod()))
                .jwkSetUri(conf.getJwkSetUri())
                .userInfoUri(conf.getUserInfoUri())
                .build();
        return clientRegistration;
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
    private ClientRegistration clientRegistration() throws ParseException {
        try {
            if (this.aimsConfig.isEnabled()) {
                logger.info(":::::::::::::::::::::::::Construyendo WSO2 ClientRegistrationRepository::::::::::::::::");
                String realm_url = this.authUrl + "/realms/" + this.realm;
                logger.info("realm_url="+realm_url);
                logger.info("wellKnownOpenidConfigurationUrl="+wellKnownOpenidConfigurationUrl);
                String issuer  = this.issuerUri;// (String) getIssuer(URI.create(realm_url), this.realm).get();
                logger.info("issuer="+issuer);
                if(this.wellKnownOpenidConfigurationUrl!=null){
                    realm_url=this.wellKnownOpenidConfigurationUrl;
                    logger.info("realm_url=wellKnownOpenidConfigurationUrl="+issuer);
                }
                else{
                    realm_url+="/.well-known/openid-configuration";
                    logger.info("realm_url+=/.well-known/openid-configuration");
                }
                if(this.issuerUri!=null){
                    issuer=this.issuerUri;
                    logger.info("issuerUri!=null");
                }
                else {
                    issuer = (String) getIssuer(URI.create(realm_url), this.realm).get();
                    logger.info("issuer=(String) getIssuer(URI.create(realm_url), this.realm).get()="+issuer);
                }

                AtomicReference<ClientRegistration.Builder> builder = new AtomicReference();
                String finalIssuer = issuer;
                String finalRealm_url = realm_url;
                TaskUtils.retry(10, 1000L, logger, () -> {
                    builder.set((ClientRegistration.Builder) getRfc8414Builder(URI.create(finalIssuer), URI.create(finalRealm_url)).get());
                    logger.info("retry finalIssuer:"+finalIssuer);
                    logger.info("retry finalRealm_url:"+finalRealm_url);
                });
                ClientRegistration registry = ((ClientRegistration.Builder) builder.get())
                        .registrationId(this.clientId)
                        .clientId(this.clientId)
                        .clientSecret(this.clientSecret)
                        .scope(new String[]{"openid"})
                        .redirectUri("*").userNameAttributeName(this.principalAttribute)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .clientName(this.clientId).build();
                return registry;
            } else {
                return null;
            }
        }
        catch (Exception ex){
            logger.error(ex.getMessage());
        }
        return null;
    }

    @Bean
    public MappingJackson2HttpMessageConverter jsonConverter() {
        List<MediaType> supportedMediaTypes = new ArrayList();
        supportedMediaTypes.add(MediaType.APPLICATION_JSON);
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.serializationInclusion(Include.NON_NULL);
        MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter(builder.build());
        jsonConverter.setSupportedMediaTypes(supportedMediaTypes);
        return jsonConverter;
    }

    private static Optional<String> getIssuer(URI realm_url, String realm) throws ParseException {
        URI uri = UriComponentsBuilder.fromUri(realm_url).replacePath(realm_url.getPath() + "/.well-known/openid-configuration").build(Collections.emptyMap());
        RequestEntity<Void> request = RequestEntity.get(uri).build();
        String configuration = (String)rest.exchange(request, String.class).getBody();
        OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(configuration);
        return Optional.of((String)Optional.of(metadata).map(AuthorizationServerMetadata::getIssuer).map(Identifier::getValue).orElse(UriComponentsBuilder.fromUriString(realm_url.toString()).pathSegment(new String[]{"realms", realm}).build().toString()));
    }

    private static Supplier<ClientRegistration.Builder> getRfc8414Builder(URI issuer, URI uri) {
        return () -> {
            RequestEntity<Void> request = RequestEntity.get(uri).build();
            Map<String, Object> configuration = (Map)rest.exchange(request, typeReference).getBody();
            AuthorizationServerMetadata metadata = (AuthorizationServerMetadata)parse(configuration, AuthorizationServerMetadata::parse);
            ClientRegistration.Builder builder = withProviderConfiguration(metadata, issuer.toASCIIString());
            URI jwkSetUri = metadata.getJWKSetURI();
            if (jwkSetUri != null) {
                builder.jwkSetUri(jwkSetUri.toASCIIString());
            }

            String userinfoEndpoint = (String)configuration.get("userinfo_endpoint");
            if (userinfoEndpoint != null) {
                builder.userInfoUri(userinfoEndpoint);
            }

            return builder;
        };
    }

    private static ClientRegistration.Builder withProviderConfiguration(AuthorizationServerMetadata metadata, String issuer) {
        String metadataIssuer = metadata.getIssuer().getValue();
        if (!issuer.equals(metadataIssuer)) {
            throw new IllegalStateException("The Issuer \"" + metadataIssuer + "\" provided in the configuration metadata did not match the requested issuer \"" + issuer + "\"");
        } else {
            String name = URI.create(issuer).getHost();
            ClientAuthenticationMethod method = getClientAuthenticationMethod(issuer, metadata.getTokenEndpointAuthMethods());
            List<GrantType> grantTypes = metadata.getGrantTypes();
            if (grantTypes != null && !grantTypes.contains(GrantType.AUTHORIZATION_CODE)) {
                throw new IllegalArgumentException("Only AuthorizationGrantType.AUTHORIZATION_CODE is supported. The issuer \"" + issuer + "\" returned a configuration of " + grantTypes);
            } else {
                List<String> scopes = getScopes(metadata);
                Map<String, Object> configurationMetadata = new LinkedHashMap(metadata.toJSONObject());
                return ClientRegistration.withRegistrationId(name).userNameAttributeName("sub").scope(scopes).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).clientAuthenticationMethod(method).redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}").authorizationUri(metadata.getAuthorizationEndpointURI().toASCIIString()).providerConfigurationMetadata(configurationMetadata).tokenUri(metadata.getTokenEndpointURI().toASCIIString()).clientName(issuer);
            }
        }
    }

    private static ClientAuthenticationMethod getClientAuthenticationMethod(String issuer, List<com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod> metadataAuthMethods) {
        if (metadataAuthMethods != null && !metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
                return ClientAuthenticationMethod.CLIENT_SECRET_POST;
            } else if (metadataAuthMethods.contains(com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.NONE)) {
                return ClientAuthenticationMethod.NONE;
            } else {
                throw new IllegalArgumentException("Only ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST and ClientAuthenticationMethod.NONE are supported. The issuer \"" + issuer + "\" returned a configuration of " + metadataAuthMethods);
            }
        } else {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
    }

    private static List<String> getScopes(AuthorizationServerMetadata metadata) {
        Scope scope = metadata.getScopes();
        return scope == null ? Collections.singletonList("openid") : scope.toStringList();
    }

    private static <T> T parse(Map<String, Object> body, ThrowingFunction<JSONObject, T, ParseException> parser) {
        try {
            return parser.apply(new JSONObject(body));
        } catch (ParseException var3) {
            throw new RuntimeException(var3);
        }
    }

    private interface ThrowingFunction<S, T, E extends Throwable> {
        T apply(S var1) throws E;
    }
}
