package cu.entalla.loader;

import cu.entalla.config.Wso2SecurityConfig;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.AbstractRefreshableConfigApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.AbstractResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.UrlResource;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

public class DynamicBeanLoader {

    private Object applicationContext;
    private static final Logger logger = Logger.getLogger(DynamicBeanLoader.class.getName());

    private Map<String,Object> loadedBeans=new HashMap<>();
    public DynamicBeanLoader(Object applicationContext ) {
        if (applicationContext instanceof ConfigurableApplicationContext)
            this.applicationContext =(ConfigurableApplicationContext) applicationContext;
        else if(applicationContext instanceof ConfigurableWebApplicationContext)
            this.applicationContext =(ConfigurableWebApplicationContext) applicationContext;
        else
            this.applicationContext =applicationContext;
    }
    public DynamicBeanLoader() {
        this.applicationContext=new AbstractRefreshableConfigApplicationContext() {
            @Override
            protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException, IOException {

            }
        };
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
    public void register(AbstractResource resource, GenericApplicationContext dynamicContext, ConfigurableListableBeanFactory beanFactory){
        //applicationContext.getBeanFactory()
        if (applicationContext instanceof ConfigurableApplicationContext||applicationContext instanceof ConfigurableWebApplicationContext){
            //dynamicContext = new GenericApplicationContext();
            XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(dynamicContext);
            reader.loadBeanDefinitions(resource);
            //beanFactory = dynamicContext.getBeanFactory();
        } else {
            beanFactory = null;
            dynamicContext = null;
        }

        if(dynamicContext!=null && beanFactory!=null){
            dynamicContext.refresh();
            // Registra los nuevos beans en el contexto principal
            GenericApplicationContext finalDynamicContext = dynamicContext;
            ConfigurableListableBeanFactory finalBeanFactory = beanFactory;
            beanFactory.getBeanNamesIterator().forEachRemaining(beanName -> {
                logger.info("Iniciando registro de bean:"+beanName);
                Object bean = finalDynamicContext.getBean(beanName);
                logger.info("Bean "+beanName+" cargado...");
                if (applicationContext instanceof ConfigurableApplicationContext){
                    ConfigurableApplicationContext tmp=((ConfigurableApplicationContext)this.applicationContext);
                    tmp.refresh();
                    if (!finalBeanFactory.containsSingleton(beanName)) {
                        logger.info("Registrando bean:"+beanName);
                        tmp.getBeanFactory().registerSingleton(beanName, bean);
                        loadedBeans.putIfAbsent(beanName,bean);
                        logger.info("Registrado el bean:"+beanName);
                    } else {
                        logger.warning("El bean con nombre " + beanName + " ya está registrado.");
                    }

                }
                else if (applicationContext instanceof ConfigurableWebApplicationContext)
                {
                    ConfigurableWebApplicationContext tmp= ((ConfigurableWebApplicationContext)this.applicationContext);
                    tmp.refresh();
                    if (!finalBeanFactory.containsSingleton(beanName)) {
                        logger.info("Registrando bean:"+beanName);
                        tmp.getBeanFactory().registerSingleton(beanName, bean);
                        logger.info("Registrado el bean:"+beanName);
                    } else {
                        logger.warning("El bean con nombre " + beanName + " ya está registrado.");
                    }
                }
            });
        }
    }
    public void loadCustomBeans(String propertiesFilePath) throws IOException {
        // Leer el archivo alfresco-global.properties

        String[] filePaths = getFilePaths(propertiesFilePath);

        // Procesar cada ruta y cargar los beans
        for (String filePath : filePaths) {
            try {
                UrlResource resource = new UrlResource(filePath.trim());
                if (resource.exists()) {
                    System.out.println("Cargando configuración desde: " + filePath);
                    GenericApplicationContext dynamicContext;
                    ConfigurableListableBeanFactory beanFactory;
                    if (applicationContext instanceof ConfigurableApplicationContext||applicationContext instanceof ConfigurableWebApplicationContext){
                        dynamicContext = new GenericApplicationContext();
                        XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(dynamicContext);
                        reader.loadBeanDefinitions(new InputStreamResource(resource.getInputStream()));
                        beanFactory = dynamicContext.getBeanFactory();
                    } else {
                        beanFactory = null;
                        dynamicContext = null;
                    }
                    if(dynamicContext!=null && beanFactory!=null){
                        register(resource,dynamicContext,beanFactory);
                    }

                } else {
                    System.err.println("No se pudo acceder a la ruta: " + filePath);
                }
            } catch (Exception e) {
                System.err.println("Error al cargar configuración desde: " + filePath);
                e.printStackTrace();
            }
        }
    }


    public void loadCustomBeans(String propertiesFilePath, BeanDefinitionRegistry registry) throws IOException {

        String[] filePaths = getFilePaths(propertiesFilePath);
        // Procesar cada ruta y cargar los beans
        for (String filePath : filePaths) {
            try {
                UrlResource resource = new UrlResource(filePath.trim());
                if (resource.exists()) {
                    System.out.println("Cargando configuración desde: " + filePath);
                    GenericApplicationContext dynamicContext=registry instanceof GenericApplicationContext? (GenericApplicationContext) registry: new GenericApplicationContext();
                    ConfigurableListableBeanFactory beanFactory;
                    if (applicationContext instanceof ConfigurableApplicationContext||applicationContext instanceof ConfigurableWebApplicationContext){
                        XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(dynamicContext);
                        reader.loadBeanDefinitions(new InputStreamResource(resource.getInputStream()));
                        beanFactory = dynamicContext.getBeanFactory();
                    } else {
                        beanFactory = null;
                        dynamicContext = null;
                    }
                    if(dynamicContext!=null && beanFactory!=null){
                        register(resource,dynamicContext,beanFactory);
                    }

                } else {
                    System.err.println("No se pudo acceder a la ruta: " + filePath);
                }
            } catch (Exception e) {
                System.err.println("Error al cargar configuración desde: " + filePath);
                e.printStackTrace();
            }
        }
    }
    public void loadCustomBeans() throws IOException {

        Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create().loadProperties();
        String[] filePaths = getFilePaths(wso2SecurityConfig.getProperties());
        // Procesar cada ruta y cargar los beans
        for (String filePath : filePaths) {
            try {
                UrlResource resource = new UrlResource(filePath.trim());
                if (resource.exists()) {
                    System.out.println("Cargando configuración desde: " + filePath);
                    GenericApplicationContext dynamicContext=new GenericApplicationContext();
                    ConfigurableListableBeanFactory beanFactory;
                    if (applicationContext instanceof ConfigurableApplicationContext||applicationContext instanceof ConfigurableWebApplicationContext){
                        XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(dynamicContext);
                        reader.loadBeanDefinitions(new InputStreamResource(resource.getInputStream()));
                        beanFactory = dynamicContext.getBeanFactory();
                    } else {
                        beanFactory = null;
                        dynamicContext = null;
                    }
                    if(dynamicContext!=null && beanFactory!=null){
                        register(resource,dynamicContext,beanFactory);
                    }

                } else {
                    System.err.println("No se pudo acceder a la ruta: " + filePath);
                }
            } catch (Exception e) {
                System.err.println("Error al cargar configuración desde: " + filePath);
                e.printStackTrace();
            }
        }
    }
    public void loadBeansFromXml(String xmlFilePath) {
        try {
            GenericApplicationContext dynamicContext = new GenericApplicationContext();
            XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(dynamicContext);

            // Lee el archivo XML de configuración
            reader.loadBeanDefinitions(new FileSystemResource(xmlFilePath));
            // Refresca el contexto dinámico
            dynamicContext.refresh();
            ConfigurableListableBeanFactory beanFactory = dynamicContext.getBeanFactory();
            // Registra los nuevos beans en el contexto principal
            beanFactory.getBeanNamesIterator().forEachRemaining(beanName -> {
                logger.info("Iniciando registro de bean:"+beanName);
                Object bean = dynamicContext.getBean(beanName);
                logger.info("Bean "+beanName+" cargado...");
                if (applicationContext instanceof ConfigurableApplicationContext){
                    ConfigurableApplicationContext tmp=((ConfigurableApplicationContext)this.applicationContext);
                    tmp.refresh();
                    if (!beanFactory.containsSingleton(beanName)) {
                        logger.info("Registrando bean:"+beanName);
                        tmp.getBeanFactory().registerSingleton(beanName, bean);
                        loadedBeans.putIfAbsent(beanName,bean);
                        logger.info("Registrado el bean:"+beanName);
                    } else {
                        logger.warning("El bean con nombre " + beanName + " ya está registrado.");
                    }

                }
                else if (applicationContext instanceof ConfigurableWebApplicationContext)
                {
                    ConfigurableWebApplicationContext tmp= ((ConfigurableWebApplicationContext)this.applicationContext);
                    tmp.refresh();
                    if (!beanFactory.containsSingleton(beanName)) {
                        logger.info("Registrando bean:"+beanName);
                        tmp.getBeanFactory().registerSingleton(beanName, bean);
                        logger.info("Registrado el bean:"+beanName);
                    } else {
                        logger.warning("El bean con nombre " + beanName + " ya está registrado.");
                    }
                }
            });
            dynamicContext.close();
        } catch (Exception e) {
            throw new RuntimeException("Error al cargar beans desde el archivo XML: " + xmlFilePath, e);
        }
    }
    public Map<String,Object> getBeansLoaded(){
        return loadedBeans;
    }
}
