package cu.entalla.loader;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.AbstractRefreshableConfigApplicationContext;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.logging.Logger;

public class Wso2PostConfigLoader implements ServletContextListener {

    List<String> xmlFilePaths;
    private static final Logger logger = Logger.getLogger(Wso2PostConfigLoader.class.getName());
    DynamicBeanLoader beanLoader;

    public Wso2PostConfigLoader(){

        xmlFilePaths =new ArrayList<>();
    }
    private String[] getFilePaths(String propertiesFilePath){
        // Leer el archivo alfresco-global.properties
        Properties properties = new Properties();
        try (FileInputStream fis = new FileInputStream(propertiesFilePath)) {
            properties.load(fis);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String configKeyFiles = properties.getProperty("custom.bean.config.keyFilesName","custom.bean.config.files");
        // Obtener la lista de rutas
        String configFiles = properties.getProperty(configKeyFiles);
        if (configFiles == null || configFiles.isEmpty()) {
            System.out.println("No se encontraron rutas de configuración en 'custom.bean.config.files'.");
            return new String[0];
        }
        return configFiles.split(",");
    }
    private String[] getFilePaths(Properties properties){
        // Leer el archivo alfresco-global.properties
        String configKeyFiles = properties.getProperty("custom.bean.config.keyFilesName","custom.bean.config.files");
        // Obtener la lista de rutas
        String configFiles = properties.getProperty(configKeyFiles);
        if (configFiles == null || configFiles.isEmpty()) {
            System.out.println("No se encontraron rutas de configuración en 'custom.bean.config.files'.");
            return new String[0];
        }
        return configFiles.split(",");
    }
    public Wso2PostConfigLoader(String... files){
        xmlFilePaths =new ArrayList<>();
        xmlFilePaths.addAll(Arrays.stream(files).toList());
    }
    public Wso2PostConfigLoader(List<String> xmlFileNames){
        setXmlFilePaths(xmlFileNames);
    }

    public static File getFileFromPath(String path)   {
        File file;
        if (path.startsWith("file:")) {
            // Convertir la ruta con prefijo "file:" a un objeto URI y luego a File
            URI uri = null;
            try {
                uri = new URI(path);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
          return   file = new File(uri);
        } else {
            // Crear el File directamente si no tiene el prefijo "file:"
           return  file = new File(path);
        }
    }
    public Wso2PostConfigLoader(String file){
        xmlFilePaths =new ArrayList<>();
        File tmp=getFileFromPath(file);
        if(tmp.exists() && tmp.isFile() && tmp.getName().endsWith(".xml") && tmp.canRead() && tmp.canWrite()) {
            xmlFilePaths.add(file);
        }
        else if(tmp.exists() && tmp.isFile() && tmp.getName().endsWith(".properties") && tmp.canRead() && tmp.canWrite()) {
            String[] filePaths = getFilePaths(tmp.getAbsolutePath());
           List list= Arrays.stream(filePaths).map(el->{
                File f=getFileFromPath(el.replace("file:",""));
                if(f.exists() && f.isFile() && f.getName().endsWith(".xml") && f.canRead()) {
                    xmlFilePaths.add(f.getAbsolutePath());
                    return el;
                }
                else if(f.exists() && f.isDirectory() && f.canRead()){
                    // Si es un directorio, listar y filtrar archivos
                    File[] filteredFiles = f.listFiles(ff ->
                            ff.isFile() &&
                                    ff.getName().endsWith(".xml") &&
                                    ff.canRead() &&
                                    ff.canWrite() &&  xmlFilePaths.add(ff.getAbsolutePath())
                    );
                }
                return el;
            }).toList();
        }
        else if(tmp.exists() && tmp.isDirectory() && tmp.canRead()){
            // Si es un directorio, listar y filtrar archivos
            File[] filteredFiles = tmp.listFiles(f ->
                    f.isFile() &&
                            f.getName().endsWith(".xml") &&
                            f.canRead() &&
                            f.canWrite() &&  xmlFilePaths.add(f.getAbsolutePath())
            );
        }
    }
    public Wso2PostConfigLoader setXmlFilePaths(List<String> xmlFilePaths){
        this.xmlFilePaths = xmlFilePaths;
        return this;
    }


    public Wso2PostConfigLoader load(){
        logger.info("Loading beans from files...");
        ConfigurableApplicationContext configurable=new AbstractRefreshableConfigApplicationContext() {
            @Override
            protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException, IOException {
               // beanFactory.registerSingleton("beanTest",new BeanTest());
                logger.info("loadBeanDefinitions finish...");
            }
        };
        logger.info("DynamicBeanLoader inicialized...");
        beanLoader = new DynamicBeanLoader(configurable);
        xmlFilePaths.forEach(xmlConfigPath->{
            beanLoader.loadBeansFromXml(xmlConfigPath);
            logger.info("Beans cargados dinámicamente desde: " + xmlConfigPath);
        });
        return this;
    }
    public Wso2PostConfigLoader load(ConfigurableApplicationContext configurableContext){
        beanLoader = new DynamicBeanLoader(configurableContext);
        xmlFilePaths.forEach(xmlConfigPath->{
            beanLoader.loadBeansFromXml(xmlConfigPath);
            logger.info("Beans cargados dinámicamente desde: " + xmlConfigPath);
        });
        return this;
    }
    public Wso2PostConfigLoader load(ConfigurableWebApplicationContext configurableContext){
        beanLoader = new DynamicBeanLoader(configurableContext);
        xmlFilePaths.forEach(xmlConfigPath->{
            beanLoader.loadBeansFromXml(xmlConfigPath);
            logger.info("Beans cargados dinámicamente desde: " + xmlConfigPath);
        });
        return this;
    }
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext servletContext = sce.getServletContext();
        WebApplicationContext springContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);

        if (springContext != null) {
            if (springContext instanceof ConfigurableApplicationContext) {
                load((ConfigurableApplicationContext) springContext);
            }
            else if(springContext instanceof ConfigurableWebApplicationContext)
                load((ConfigurableWebApplicationContext) springContext);
            else
                throw new IllegalStateException("El contexto de Spring no es una instancia de ConfigurableApplicationContext." );

        }
        else
            throw new IllegalStateException("No se pudo obtener el contexto de Spring.");

    }
    public Map<String,Object> getBeansLoaded(){
        return beanLoader!=null?beanLoader.getBeansLoaded():new HashMap<>();
    }
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // Limpieza si es necesario
    }
}
