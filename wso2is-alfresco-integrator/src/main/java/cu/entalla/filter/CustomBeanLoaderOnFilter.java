package cu.entalla.filter;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.loader.Wso2PostConfigLoader;
import cu.entalla.security.EnTallaTrustManager;
import cu.entalla.service.AuthenticationService;
import cu.entalla.store.CookieManager;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;
import java.util.logging.Logger;

@WebFilter(urlPatterns = {"/alfresco/*", "/share/*"})
public class CustomBeanLoaderOnFilter implements Filter {

    private Wso2SecurityConfig wso2SecConfig;
    private AuthenticationService authService=new AuthenticationService();

    private EnTallaTrustManager trustManager;

    private String redirectPage="/alfresco";

    String catalinaBase = System.getenv("CATALINA_BASE");
    private static final Logger logger = Logger.getLogger(CustomBeanLoaderOnFilter.class.getName());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        try {
            redirectPage=filterConfig.getInitParameter("redirectPage");
            if(redirectPage==null||redirectPage!=null && !redirectPage.isEmpty())
                redirectPage="/alfresco";
            ApplicationContext webApplicationContext= WebApplicationContextUtils.getWebApplicationContext(filterConfig.getServletContext());
            SpringContextHolder.registry(redirectPage,webApplicationContext);
            SpringContextHolder.setApplicationContext(redirectPage,webApplicationContext);
            logger.info("...................Guardando contexto ["+redirectPage+"] spring-hazelcast con Servlet CustomBeanLoaderOnFilter............");
            // Obtener el valor de CATALINA_BASE
            catalinaBase = System.getenv("CATALINA_BASE");
            if(catalinaBase==null) {
                catalinaBase = filterConfig.getInitParameter("CATALINA_BASE");// "/media/datos/Instaladores/entalla/tomcat";
                System.setProperty("CATALINA_BASE",catalinaBase);
            }
            if(catalinaBase!=null)
            {
                String configFile=catalinaBase + "/shared/classes/alfresco-global.properties";
                try {
                    logger.info("INICIANDO CARGA DE BEANS PERSONALIZADOS...");
                    Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFile);
                    Wso2PostConfigLoader loader = new Wso2PostConfigLoader(configFile);
                    loader.load();
                    logger.info("FINALIZA CARGA DE BEANS PERSONALIZADOS...");
                }
                catch (Exception ex){
                    logger.severe("ERROR CARGANDO BEANS PERSONALIZADOS"+ex.getMessage());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        CookieManager manager=  CookieManager.getInstance().setRequest((HttpServletRequest) request).setResponse((HttpServletResponse) response);

        String error = manager.getParameter("error");
        // Manejo de errores
        if (error != null) {
            String errorDescription = manager.getParameter("error_description");
            logger.severe("Error en la autenticación: " + error + " - " + errorDescription);
            manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error en la autenticación: " + errorDescription);
            return;
        }
        String configFile=catalinaBase + "/shared/classes/alfresco-global.properties";
        try {
            logger.info("###############################INICIANDO CARGA DE BEANS PERSONALIZADOS###########################\n");
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFile);
            Wso2PostConfigLoader loader = new Wso2PostConfigLoader(configFile);
            loader.load();
            logger.info("FINALIZA CARGA DE BEANS PERSONALIZADOS...");
        }
        catch (Exception ex){
            logger.severe("\n\n\n"+ex.getMessage()+"\n\n\n");
            logger.severe("###############################TERMINANDO CARGA DE BEANS PERSONALIZADOS###########################\n");
            manager.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error intentar cargar los beans especificados en la propiedad [custom.bean.config.keyFilesName] que debe estar declarada en:"+configFile);
        }
        // Continuar con la cadena de filtros si está autenticado
        chain.doFilter(request, response);
    }

    private boolean isAuthenticated(HttpServletRequest request) {
        // Verificar si el usuario ya está autenticado
        String user = (String) request.getSession().getAttribute("authenticatedUser");
        return user != null;
    }

    @Override
    public void destroy() {
        // Limpiar recursos si es necesario
    }
}
