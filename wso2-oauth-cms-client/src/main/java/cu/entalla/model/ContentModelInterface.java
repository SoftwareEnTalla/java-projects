package cu.entalla.model;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public interface ContentModelInterface/* extends ContentModel*/{
    public void authenticateUser(String username, String email, String phone);
    //public void createUser(Map<QName, Serializable> properties);
    public String createSession(OAuth2AuthenticationToken authentication);
}