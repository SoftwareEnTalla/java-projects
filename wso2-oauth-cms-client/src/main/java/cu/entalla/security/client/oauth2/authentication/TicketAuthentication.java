package cu.entalla.security.client.oauth2.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;

public class TicketAuthentication extends OAuth2LoginAuthenticationToken implements Authentication {

    private final String accessToken;
    private final String ticket;
    private final String username;
    private final Collection<GrantedAuthority> authorities;

    private final java.util.Map<String, Object> attributes;
    private boolean authenticated;

    public TicketAuthentication(ClientRegistration clientRegistration, OAuth2AuthorizationExchange authorizationExchange, String accessToken, String ticket, String username,
                                Collection<GrantedAuthority> authorities, java.util.Map<String, Object> attributes) {
        super(clientRegistration,authorizationExchange);
        this.accessToken = accessToken;
        this.ticket = ticket;
        this.username = username;
        this.authorities = authorities;
        this.attributes=attributes;
        this.authenticated = true;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return accessToken; // El accessToken actúa como credencial
    }

    @Override
    public Object getDetails() {
        return ticket; // Opcionalmente, puedes incluir más detalles
    }

    @Override
    public OAuth2User getPrincipal() {
        return new DefaultOAuth2User(authorities,this.attributes,"username"); // El usuario autenticado
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return username;
    }
}
