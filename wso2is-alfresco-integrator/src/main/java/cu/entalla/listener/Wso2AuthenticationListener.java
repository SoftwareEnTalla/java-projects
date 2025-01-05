package cu.entalla.listener;

import cu.entalla.security.authentication.Wso2AuthenticationConfig;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.util.logging.Logger;

@WebListener
public class Wso2AuthenticationListener implements ServletContextListener {

    private static final Logger logger = Logger.getLogger(Wso2AuthenticationListener.class.getName());
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        // Llamamos al método de inicialización solo después de que el contexto de la aplicación haya sido cargado
        logger.info("Se comienza a inicializar la configuración de Wso2AuthenticationConfig...." +
                "....................................................................................");
        //Wso2AuthenticationConfig.getInstanceOfWso2AuthenticationConfig().init();
        //Wso2AuthenticationConfig.getInstanceOfWso2AuthenticationConfig().configureNameSpacePrefixResolver();
        logger.info("Se termina de inicializar la configuración de Wso2AuthenticationConfig...." +
                "....................................................................................");
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // Aquí puedes agregar código si deseas limpiar recursos al cerrar el contexto
    }
}
