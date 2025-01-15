package cu.entalla.security.oauth2.client.oidc.authentication;


import java.util.function.Function;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

public class EnTallaOidcIdTokenValidatorFactory implements Function<ClientRegistration, OAuth2TokenValidator<Jwt>> {
    public EnTallaOidcIdTokenValidatorFactory() {
    }

    public OAuth2TokenValidator<Jwt> apply(ClientRegistration clientRegistration) {
        return new DelegatingOAuth2TokenValidator(new OAuth2TokenValidator[]{new JwtTimestampValidator(), new OidcIdTokenValidator(clientRegistration)});
    }
}
