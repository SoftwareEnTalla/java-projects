package cu.entalla;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.service.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "cu.entalla")
public class Wso2OAuthApplication implements CommandLineRunner {
    static AuthenticationService service;
    public static void main(String[] args) throws Exception {
        String catalinaBase = System.getenv("CATALINA_BASE");
        if(catalinaBase==null) {
            catalinaBase = "/media/datos/Instaladores/entalla/tomcat";
            System.setProperty("CATALINA_BASE",catalinaBase);
        }
        if(catalinaBase!=null){
             service=new AuthenticationService().initWso2AuthenticatorClient();
            if(!service.hasOpenIdConfigurationLoaded())
                service.discoverOidcEndPoints(catalinaBase+"/shared/classes/alfresco-global.properties");

        }
        SpringContextHolder.setApplicationContext("/alfresco",SpringApplication.run(Wso2OAuthApplication.class, args));
    }

    @Override
    public void run(String... args) throws Exception {
        service.authenticationWithCodeFlow("wso2");
    }
}