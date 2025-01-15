//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private OAuth2AuthorizationRequestResolver defaultResolver;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository repo, String authorizationRequestBaseUri) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repo, authorizationRequestBaseUri);
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = this.defaultResolver.resolve(httpServletRequest);
        if (oAuth2AuthorizationRequest != null) {
            oAuth2AuthorizationRequest = this.customizeAuthorizationRequest(oAuth2AuthorizationRequest, httpServletRequest);
        }

        return oAuth2AuthorizationRequest;
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest, String clientRegistrationId) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = this.defaultResolver.resolve(httpServletRequest, clientRegistrationId);
        if (oAuth2AuthorizationRequest != null) {
            oAuth2AuthorizationRequest = this.customizeAuthorizationRequest(oAuth2AuthorizationRequest, httpServletRequest);
        }

        return oAuth2AuthorizationRequest;
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest req, HttpServletRequest request) {
        return OAuth2AuthorizationRequest.from(req).redirectUri(String.valueOf(request.getRequestURL())).build();
    }
}
