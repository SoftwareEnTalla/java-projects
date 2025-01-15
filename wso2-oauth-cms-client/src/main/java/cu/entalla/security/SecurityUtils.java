package cu.entalla.security;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.ServletException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public class SecurityUtils {
    public SecurityUtils() {
    }

    public static boolean isAuthorizationResponse(MultiValueMap<String, String> request) {
        return isAuthorizationResponseSuccess(request) || isAuthorizationResponseError(request);
    }

    static boolean isAuthorizationResponseSuccess(MultiValueMap<String, String> request) {
        return StringUtils.hasText((String)request.getFirst("code")) && StringUtils.hasText((String)request.getFirst("state"));
    }

    static boolean isAuthorizationResponseError(MultiValueMap<String, String> request) {
        return StringUtils.hasText((String)request.getFirst("error")) && StringUtils.hasText((String)request.getFirst("state"));
    }

    public static MultiValueMap<String, String> toMultiMap(Map<String, String[]> map) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap(map.size());
        map.forEach((key, values) -> {
            if (values.length > 0) {
                String[] var3 = values;
                int var4 = values.length;

                for(int var5 = 0; var5 < var4; ++var5) {
                    String value = var3[var5];
                    params.add(key, value);
                }
            }

        });
        return params;
    }

    public static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
        String code = (String)request.getFirst("code");
        String errorCode = (String)request.getFirst("error");
        String state = (String)request.getFirst("state");
        if (StringUtils.hasText(code)) {
            return OAuth2AuthorizationResponse.success(code).redirectUri(redirectUri).state(state).build();
        } else {
            String errorDescription = (String)request.getFirst("error_description");
            String errorUri = (String)request.getFirst("error_uri");
            return OAuth2AuthorizationResponse.error(errorCode).redirectUri(redirectUri).errorDescription(errorDescription).errorUri(errorUri).state(state).build();
        }
    }

    public static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
        public DefaultThrowableAnalyzer() {
        }

        protected void initExtractorMap() {
            super.initExtractorMap();
            this.registerExtractor(ServletException.class, (throwable) -> {
                ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
                return ((ServletException)throwable).getRootCause();
            });
        }
    }

    public Map<String, Object> extractAdditionalPropertiesFromToken(String accessToken) throws AuthenticationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            // Extraer propiedades adicionales según tus necesidades
            Map<String, Object> additionalProperties = new HashMap<>();
            additionalProperties.put("firstName", claims.getStringClaim("given_name"));
            additionalProperties.put("lastName", claims.getStringClaim("family_name"));

            return additionalProperties;
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for additional properties", e);
        }
    }
    public String getUsernameFromToken(String accessToken) throws AuthenticationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("username");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token", e);
        }
    }
    public String getExpireInFromToken(String accessToken) throws AuthenticationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getDateClaim("exp").toString();
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token", e);
        }
    }
    public String getPhoneFromToken(String accessToken) throws AuthenticationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("phone");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for phone", e);
        }
    }
    public String getEmailFromToken(String accessToken) throws AuthenticationException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("email");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for email", e);
        }
    }
}