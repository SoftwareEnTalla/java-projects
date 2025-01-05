package cu.entalla.model;

import org.alfresco.model.ContentModel;
import org.alfresco.service.namespace.QName;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import java.io.Serializable;
import java.util.Map;

public interface AlfrescoContentModelInterface extends ContentModel{
    public void authenticateUser(String username, String email, String phone);
    public void createUser(Map<QName, Serializable> properties);
    public String createAlfrescoSession(OAuth2AuthenticationToken authentication);
}
