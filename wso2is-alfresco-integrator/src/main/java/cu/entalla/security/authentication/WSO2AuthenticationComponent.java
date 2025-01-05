package cu.entalla.security.authentication;

import org.alfresco.repo.security.authentication.AuthenticationComponentImpl;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.springframework.stereotype.Component;

@Component
public class WSO2AuthenticationComponent extends AuthenticationComponentImpl {


    private AuthenticationService authenticationService;

    public WSO2AuthenticationComponent(AuthenticationService authenticationService) {
        super();
        this.authenticationService = authenticationService!=null?authenticationService:new WSO2AuthenticationServiceImpl();
    }
    public WSO2AuthenticationComponent() {
        super();
        this.authenticationService = new WSO2AuthenticationServiceImpl();
    }

    @Override
    public void authenticate(String userName, char[] password) throws AuthenticationException {
        // Llama al método de autenticación del servicio configurado
        authenticationService.authenticate(userName, password);
    }


    public void authenticate(String userName) throws AuthenticationException {
        // Aquí puedes implementar lógica adicional si es necesario, pero delega al servicio
        throw new UnsupportedOperationException("Use authenticate with password or accessToken");
    }


    public void authenticateAsGuest() throws AuthenticationException {
        throw new UnsupportedOperationException("Guest authentication is not supported.");
    }

    public void authenticateWithToken(String accessToken) throws AuthenticationException {
        if (authenticationService instanceof WSO2AuthenticationServiceImpl) {
            ((WSO2AuthenticationServiceImpl) authenticationService).authenticateWithToken(accessToken);
        } else {
            throw new AuthenticationException("Authentication service does not support token authentication.");
        }
    }

    @Override
    public boolean guestUserAuthenticationAllowed() {
        return false;
    }
}
