package cu.entalla.security.pkce;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;

public class PKCEAuthorizationCodeTokenRequestEntityConverter
        implements Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest request) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add(OAuth2ParameterNames.GRANT_TYPE, request.getGrantType().getValue());
        body.add(OAuth2ParameterNames.CODE, request.getAuthorizationExchange().getAuthorizationResponse().getCode());
        body.add(OAuth2ParameterNames.REDIRECT_URI, request.getClientRegistration().getRedirectUri());
        body.add(OAuth2ParameterNames.CLIENT_ID, request.getClientRegistration().getClientId());

        // Agregar el code_verifier para PKCE
        String codeVerifier = request.getAuthorizationExchange().getAuthorizationRequest()
                .getAttribute(EnTallaOAuth2ParameterNames.CODE_VERIFIER);
        if (codeVerifier != null) {
            body.add(EnTallaOAuth2ParameterNames.CODE_VERIFIER, codeVerifier);
        }

        return RequestEntity
                .post(URI.create(request.getClientRegistration().getProviderDetails().getTokenUri()))
                .body(body);
    }
}
