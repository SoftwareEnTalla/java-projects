package cu.entalla.security.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

@Component
public class Wso2AuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = Logger.getLogger(Wso2AuthenticationProvider.class.getName());
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcUserService();
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    public Wso2AuthenticationProvider(){
    }
    @Override
    public Authentication authenticate(Authentication authentication) {
        // Lógica personalizada para la autenticación
       /* String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        logger.info("Ejecutando authenticate for user:"+username+" with password:"+password);
        // Aquí podrías llamar a un servicio de autenticación o hacer lo que necesites
        if (username == null || password == null) {
            logger.severe("Credenciales inválidas");
            throw new BadCredentialsException("Credenciales inválidas");
        }
        return new UsernamePasswordAuthenticationToken(username, password, List.of(new SimpleGrantedAuthority("ROLE_USER"),new SimpleGrantedAuthority("ROLE_AUTHENTICATED")));
        */
        OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken)authentication;
        if (!authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
            String username = authentication.getName();
            String password = (String) authentication.getCredentials();
            return new UsernamePasswordAuthenticationToken(username, password, List.of(new SimpleGrantedAuthority("ROLE_USER"),new SimpleGrantedAuthority("ROLE_AUTHENTICATED")));
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
                    final GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> {
                        return authorities;
                    };
                    OidcUser oidcUser = (OidcUser)this.userService.loadUser(new OidcUserRequest(clientRegistration, accessTokenResponse.getAccessToken(), idToken, additionalParameters));
                    Collection<? extends GrantedAuthority> mappedAuthorities = authoritiesMapper.mapAuthorities(oidcUser.getAuthorities());
                    OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), authorizationCodeAuthentication.getAuthorizationExchange(), oidcUser, mappedAuthorities, accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken());
                    authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
                    return authenticationResult;
                }
            }
        }
    }
    private OidcIdToken createOidcToken(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
        JwtDecoder jwtDecoder = new OidcIdTokenDecoderFactory().createDecoder(clientRegistration);

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
    public boolean supports(Class<?> authentication) {
        // Definir si este proveedor soporta el tipo de autenticación
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}