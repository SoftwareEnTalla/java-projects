package cu.entalla.security.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.logging.Logger;

@Component
public class Wso2AuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = Logger.getLogger(Wso2AuthenticationProvider.class.getName());
    public Wso2AuthenticationProvider(){
    }
    @Override
    public Authentication authenticate(Authentication authentication) {
        // Lógica personalizada para la autenticación
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        logger.info("Ejecutando authenticate for user:"+username+" with password:"+password);
        // Aquí podrías llamar a un servicio de autenticación o hacer lo que necesites
        if (username == null || password == null) {
            logger.severe("Credenciales inválidas");
            throw new BadCredentialsException("Credenciales inválidas");
        }
        return new UsernamePasswordAuthenticationToken(username, password, List.of(new SimpleGrantedAuthority("ROLE_USER"),new SimpleGrantedAuthority("ROLE_AUTHENTICATED")));
        // Ejemplo: validación ficticia de usuario y contraseña
       /* if ("admin".equals(username) && "password".equals(password)) {
            // Retornar un objeto Authentication exitoso

        } else {
            throw new BadCredentialsException("Credenciales incorrectas");
        }*/
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // Definir si este proveedor soporta el tipo de autenticación
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}