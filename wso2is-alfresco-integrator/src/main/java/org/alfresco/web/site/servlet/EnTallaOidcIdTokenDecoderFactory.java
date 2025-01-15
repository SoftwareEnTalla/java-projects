package org.alfresco.web.site.servlet;


import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import cu.entalla.security.oauth2.client.oidc.authentication.EnTallaOidcIdTokenValidatorFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
public class EnTallaOidcIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
    private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";
    private static final Map<JwsAlgorithm, String> JCA_ALGORITHM_MAPPINGS;
    private static final ClaimTypeConverter DEFAULT_CLAIM_TYPE_CONVERTER;
    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap();
    private Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = new EnTallaOidcIdTokenValidatorFactory();
    private Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver = (clientRegistration) -> {
        return SignatureAlgorithm.RS256;
    };
    private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (clientRegistration) -> {
        return DEFAULT_CLAIM_TYPE_CONVERTER;
    };

    public EnTallaOidcIdTokenDecoderFactory() {
    }

    public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
        Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
        Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
        Converter<Object, ?> urlConverter = getConverter(TypeDescriptor.valueOf(URL.class));
        Converter<Object, ?> stringConverter = getConverter(TypeDescriptor.valueOf(String.class));
        Converter<Object, ?> collectionStringConverter = getConverter(TypeDescriptor.collection(Collection.class, TypeDescriptor.valueOf(String.class)));
        Map<String, Converter<Object, ?>> converters = new HashMap();
        converters.put("iss", urlConverter);
        converters.put("aud", collectionStringConverter);
        converters.put("nonce", stringConverter);
        converters.put("exp", instantConverter);
        converters.put("iat", instantConverter);
        converters.put("auth_time", instantConverter);
        converters.put("amr", collectionStringConverter);
        converters.put("email_verified", booleanConverter);
        converters.put("phone_number_verified", booleanConverter);
        converters.put("updated_at", instantConverter);
        return converters;
    }

    private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
        TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
        return (source) -> {
            return ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
        };
    }

    public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        return (JwtDecoder)this.jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), (key) -> {
            NimbusJwtDecoder jwtDecoder = this.buildDecoder(clientRegistration);
            jwtDecoder.setJwtValidator((OAuth2TokenValidator)this.jwtValidatorFactory.apply(clientRegistration));
            Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter = (Converter)this.claimTypeConverterFactory.apply(clientRegistration);
            if (claimTypeConverter != null) {
                jwtDecoder.setClaimSetConverter(claimTypeConverter);
            }

            return jwtDecoder;
        });
    }

    private NimbusJwtDecoder buildDecoder(ClientRegistration clientRegistration) {
        JwsAlgorithm jwsAlgorithm = (JwsAlgorithm)this.jwsAlgorithmResolver.apply(clientRegistration);
        String clientSecret;
        OAuth2Error oauth2Error = null;
        if (jwsAlgorithm != null && SignatureAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
            clientSecret = clientRegistration.getProviderDetails().getJwkSetUri();
            if (!StringUtils.hasText(clientSecret)) {
                oauth2Error = new OAuth2Error("missing_signature_verifier", "Failed to find a Signature Verifier for Client Registration: '" + clientRegistration.getRegistrationId() + "'. Check to ensure you have configured the JwkSet URI.", (String)null);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            } else {
                return NimbusJwtDecoder.withJwkSetUri(clientSecret).jwsAlgorithm((SignatureAlgorithm)jwsAlgorithm).build();
            }
        } else if (jwsAlgorithm != null && MacAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
            clientSecret = clientRegistration.getClientSecret();
            if (!StringUtils.hasText(clientSecret)) {
                oauth2Error = new OAuth2Error("missing_signature_verifier", "Failed to find a Signature Verifier for Client Registration: '" + clientRegistration.getRegistrationId() + "'. Check to ensure you have configured the client secret.", (String)null);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            } else {
                SecretKeySpec secretKeySpec = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), (String)JCA_ALGORITHM_MAPPINGS.get(jwsAlgorithm));
                return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm)jwsAlgorithm).build();
            }
        } else {
            OAuth2Error oAuth2Error = new OAuth2Error("missing_signature_verifier", "Failed to find a Signature Verifier for Client Registration: '" + clientRegistration.getRegistrationId() + "'. Check to ensure you have configured a valid JWS Algorithm: '" + jwsAlgorithm + "'", (String)null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
    }

    public void setJwtValidatorFactory(Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory) {
        Assert.notNull(jwtValidatorFactory, "jwtValidatorFactory cannot be null");
        this.jwtValidatorFactory = jwtValidatorFactory;
    }

    public void setJwsAlgorithmResolver(Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver) {
        Assert.notNull(jwsAlgorithmResolver, "jwsAlgorithmResolver cannot be null");
        this.jwsAlgorithmResolver = jwsAlgorithmResolver;
    }

    public void setClaimTypeConverterFactory(Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory) {
        Assert.notNull(claimTypeConverterFactory, "claimTypeConverterFactory cannot be null");
        this.claimTypeConverterFactory = claimTypeConverterFactory;
    }

    static {
        Map<JwsAlgorithm, String> mappings = new HashMap();
        mappings.put(MacAlgorithm.HS256, "HmacSHA256");
        mappings.put(MacAlgorithm.HS384, "HmacSHA384");
        mappings.put(MacAlgorithm.HS512, "HmacSHA512");
        JCA_ALGORITHM_MAPPINGS = Collections.unmodifiableMap(mappings);
        DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(createDefaultClaimTypeConverters());
    }
}