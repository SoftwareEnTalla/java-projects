package cu.entalla.app.config;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.component.AlfrescoIntegratorImpl;
import cu.entalla.config.Wso2Config;
import cu.entalla.service.ServiceLocator;
import cu.entalla.udi.ClientServiceIntegration;
import lombok.Data;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.context.ContextLoader;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

@Configuration
@Data
public class IntegratorConfig implements ApplicationContextAware {

    private static final Log logger = LogFactory.getLog(IntegratorConfig.class);
    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Bean(name = "alfrescoIntegration")
    public ClientServiceIntegration alfrescoIntegration() {
        String app = "/alfresco";
        if (applicationContext != null && applicationContext.containsBean("alfrescoIntegration")) {
            return applicationContext.getBean(AlfrescoIntegratorImpl.class);
        } else if (applicationContext != null && !applicationContext.containsBean("alfrescoIntegration")) {
            WebApplicationContext currentWebApplicationContext = ContextLoader.getCurrentWebApplicationContext();
            if (currentWebApplicationContext != null) {
                logger.info("----------------------------Creando instancia de ClientServiceIntegration----------------------------");
                // Obtener el contexto de la aplicación dinámicamente
                app = currentWebApplicationContext.getServletContext().getContextPath();
                logger.info("----------------------------Creando instancia de ClientServiceIntegration en "+app+" con alfrescoIntegration()----------------------------");

                WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(currentWebApplicationContext.getServletContext());
                try {
                    SpringContextHolder.setApplicationContext(app, webApplicationContext);
                    ClientServiceIntegration bean = SpringContextHolder.getApplicationContext(app).getBean("alfrescoIntegration",AlfrescoIntegratorImpl.class);
                    logger.info(":::::::::::::ClientServiceIntegration " + (bean != null ? "registrado satisfactoriamente en: "+app : " no registrado porque es null en: "+app) + "::::::::::::::::::::::::::::::::::::::::::::");
                    if (bean != null) {
                        ServiceLocator.registerIntegrator(bean);
                    }
                    return bean;
                } catch (Exception e) {
                    logger.error("ERROR inicializando instancia de ClientServiceIntegration en IntegratorConfig para el contexto: "+app);
                    e.printStackTrace();
                    //throw new RuntimeException(e);
                }
            }
        }
        return null;
    }


    @Bean(name = "getIntegrator")
    @Primary
    public ClientServiceIntegration getIntegrator() throws Exception {
        String app="/alfresco";
        WebApplicationContext currentWebApplicationContext = ContextLoader.getCurrentWebApplicationContext();
        if(currentWebApplicationContext!=null) {
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(currentWebApplicationContext.getServletContext());
            app = currentWebApplicationContext.getServletContext().getContextPath();
            logger.info("----------------------------Creando instancia de ClientServiceIntegration en "+app+" con getIntegrator()----------------------------");
            SpringContextHolder.setApplicationContext(app, webApplicationContext);
            ClientServiceIntegration bean = SpringContextHolder.getApplicationContext(app).getBean(AlfrescoIntegratorImpl.class);
            logger.info(":::::::::::::ClientServiceIntegration " + (bean != null ? "registrado satisfactoriamente" : " no registrado porque es null") + "::::::::::::::::::::::::::::::::::::::::::::");
            if (bean != null)
                ServiceLocator.registerIntegrator(bean);
            return bean;
        }
        logger.info("----------------------------Instancia de ClientServiceIntegration is null----------------------------");
        return null;
    }
}
