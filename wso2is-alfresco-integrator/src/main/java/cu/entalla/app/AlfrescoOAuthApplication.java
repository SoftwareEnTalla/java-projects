package cu.entalla.app;

import cu.entalla.app.context.SpringContextHolder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "cu.entalla.security.authentication")
public class AlfrescoOAuthApplication {
    public static void main(String[] args) throws Exception {
       SpringContextHolder.setApplicationContext("/alfresco",SpringApplication.run(AlfrescoOAuthApplication.class, args));
    }
}