package cu.entalla.security.authentication;

import java.util.Map;

public interface AuthenticationService {

    public void authenticate(String username, char[] password) ;

    public void authenticateWithToken(String accessToken);

    public boolean validateTokenWithWSO2(String accessToken);

    public String getUsernameFromToken(String accessToken) ;

    public Map<String,Object> getPayLoadFromToken(String accessToken) ;

}
