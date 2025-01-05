package cu.entalla.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/testing")
public class Wso2ClientController {

    @GetMapping("/test")
    public String test() {

        return "¡Hola desde wso2-client!";
    }
    @GetMapping("/wso2/oauth2/callback")
    public String handleCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "AuthenticatedIdPs", required = false) String authenticatedIdPs,
            OAuth2AuthenticationToken authentication) {

        System.out.println("Callback recibido:");
        System.out.println("Código de autorización: " + code);
        System.out.println("IDP autenticado: " + authenticatedIdPs);

        if (authentication != null && authentication.isAuthenticated()) {
            System.out.println("Usuario autenticado: " + authentication.getName());
            return "Sesión en Alfresco creada para el usuario: " + authentication.getName();
        } else {
            System.out.println("No hay autenticación válida en el token.");
            return "Error: No se pudo autenticar al usuario.";
        }
    }
    @GetMapping("/oauth2/authorization/wso2")
    public String authorizationWso2Endpoint() {
        return "Test endpoint working!";
    }
}
