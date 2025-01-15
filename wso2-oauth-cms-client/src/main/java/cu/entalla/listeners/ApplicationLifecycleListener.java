package cu.entalla.listeners;


import cu.entalla.config.Wso2SecurityConfig;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

import java.util.logging.Logger;

@WebListener
public class ApplicationLifecycleListener implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(Wso2SecurityConfig.class.getName());
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        logger.info("----------------------------Aplicación iniciada y detectada por ApplicationLifecycleListener----------------------------");
        try {
            // Construir el bean determinado
            Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create();
            wso2SecurityConfig= wso2SecurityConfig.initialize();
            // Almacenar el bean en el contexto para que otras partes de la aplicación puedan acceder
            sce.getServletContext().setAttribute("Wso2SecurityConfig", wso2SecurityConfig);
            System.out.println("Bean construido y almacenado en el contexto.");
        } catch (Exception e) {
            logger.info("----------------------------Fallo en el contextInitialized de  ApplicationLifecycleListener----------------------------\n"+e.getMessage());
            throw new RuntimeException(e);
        }


    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        logger.info("----------------------------Aplicación detenida y detectada por ApplicationLifecycleListener----------------------------");        // Limpiar recursos del bean si es necesario
        Wso2SecurityConfig config = (Wso2SecurityConfig) sce.getServletContext().getAttribute("Wso2SecurityConfig");
        if (config != null) {
            config.cleanup();
        }
    }
}