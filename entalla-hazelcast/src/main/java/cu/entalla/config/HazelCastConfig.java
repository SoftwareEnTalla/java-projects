package cu.entalla.config;

import com.hazelcast.config.ClasspathXmlConfig;
import com.hazelcast.config.Config;
import com.hazelcast.config.FileSystemXmlConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import cu.entalla.app.context.SpringContextHolder;

import cu.entalla.serializer.*;
import lombok.Data;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import org.springframework.web.context.ContextLoader;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Logger;

@Configuration
@Data
public class HazelCastConfig {



    private boolean loaded =false;

    private Properties properties = new Properties();

    private String globalPropertyFile;

    private String instanceName="softwarentalla-hazelcast-instance";

    private String classPathFileName="alfresco/extension/hazelcastConfig.xml";

    private String configFileName=System.getenv("CATALINA_BASE")+"/conf/hazelcastConfig.xml";

    public static HazelCastConfig hazelCastConfig;

    // Constructor para inicializar con la ruta del archivo de configuración
    private HazelCastConfig(String configFilePath) {
        globalPropertyFile=configFilePath;
        loaded=false;
    }
    private HazelCastConfig() {
        loaded=false;
    }
    public static Logger getLogger(){
        return  Logger.getLogger(HazelCastConfig.class.getName());
    }

    @Bean
    public HazelcastInstance hazelcastClassPathInstance(){

        getLogger().info("Hazelcast Config created... ");
        HazelCastConfig conf=HazelCastConfig.getInstance();
        if(conf==null) {
            conf = HazelCastConfig.getInstance();
            if (!conf.isLoaded())
                conf.loadProperties();
            //AuthenticationStore.getInstance().setWso2SecurityConfig(conf);
        }
        // Crear instancia de Hazelcast con la configuración cargada
        instanceName=conf.getPropertyByKey("hazelcast.instance.instanceName", "softwarentalla-hazelcast-instance");
        // Nombre del archivo en la ruta del classpath
        classPathFileName =conf.getPropertyByKey("hazelcast.instance.classPathFileName", classPathFileName);;
        // Cargar configuración desde el classpath
        Config config = new ClasspathXmlConfig(classPathFileName);
        config.setInstanceName(instanceName);
        config.getSerializationConfig()
                .getCompactSerializationConfig()
                .addSerializer(new DefaultListableBeanFactorySerializer())
                .addSerializer(new XmlWebApplicationContextSerializer())
                .addSerializer(new AtomicBooleanSerializer()).addSerializer(new ObjectSerializer())
                .addSerializer(new ListSerializer())
                .addSerializer(new MapSerializer());
        HazelcastInstance hazelcastInstance = Hazelcast.getOrCreateHazelcastInstance(config);
        getLogger().info("HazelcastInstance  created... ");
        return hazelcastInstance;
    }

    @Bean
    public HazelcastInstance hazelcastFromFileInstance() throws FileNotFoundException {

        String configFile = System.getenv("CATALINA_BASE");
        if (configFile == null) {
            configFile = "/media/datos/Instaladores/entalla/tomcat/conf/hazelcastConfig.xml";
            System.setProperty("CATALINA_BASE", configFile);
        }
        else
        {
            configFile += "/conf/hazelcastConfig.xml";
            System.setProperty("CATALINA_BASE", configFile);
        }
        HazelCastConfig conf=HazelCastConfig.getInstance();
        if (configFile != null) {
            getLogger().info("Cargando propiedades desde:" + configFile);
            if (new File(configFile).exists()) {
                conf.globalPropertyFile = configFile;
                conf.loadProperties(globalPropertyFile);
                conf.loaded = true;
            }
        } else {
            getLogger().info("No se encuentra valor para la propiedad HAZELCAST_CONFIG_FILE en las variables de entorno de JVM.");
        }
        // Crear instancia de Hazelcast con la configuración cargada
        instanceName=conf.getPropertyByKey("hazelcast.instance.instanceName", "softwarentalla-hazelcast-instance");
        // Nombre del archivo en la ruta del classpath
        configFileName =conf.getPropertyByKey("hazelcast.instance.classPathFileName", configFileName);;
        // Cargar configuración desde el classpath
        Config config = new FileSystemXmlConfig(configFileName);
        config.setInstanceName(instanceName);
        config.getSerializationConfig()
                .getCompactSerializationConfig()
                .addSerializer(new DefaultListableBeanFactorySerializer())
                .addSerializer(new XmlWebApplicationContextSerializer())
                .addSerializer(new AtomicBooleanSerializer()).addSerializer(new ObjectSerializer())
                .addSerializer(new ListSerializer())
                .addSerializer(new MapSerializer());
        HazelcastInstance hazelcastInstance = Hazelcast.getOrCreateHazelcastInstance(config);
        getLogger().info("HazelcastInstance  created... ");
        return hazelcastInstance;
    }

    public HazelcastInstance hazelcastFromFileInstance(String name,String configFile) throws FileNotFoundException {


        HazelCastConfig conf=HazelCastConfig.getInstance();
        if (configFile != null) {
            getLogger().info("Cargando propiedades desde:" + configFile);
            if (new File(configFile).exists()) {
                conf.globalPropertyFile = configFile;
                conf.loadProperties(globalPropertyFile);
                conf.loaded = true;
            }
        } else {
            getLogger().info("No se encuentra valor para la propiedad HAZELCAST_CONFIG_FILE en las variables de entorno de JVM.");
        }
        // Crear instancia de Hazelcast con la configuración cargada
        instanceName=name;
        // Nombre del archivo en la ruta del classpath
        configFileName =configFile;
        // Cargar configuración desde el classpath
        Config config = new FileSystemXmlConfig(configFile);
        config.setInstanceName(instanceName);
        config.getSerializationConfig()
                .getCompactSerializationConfig()
                .addSerializer(new DefaultListableBeanFactorySerializer())
                .addSerializer(new XmlWebApplicationContextSerializer())
                .addSerializer(new AtomicBooleanSerializer()).addSerializer(new ObjectSerializer())
                .addSerializer(new ListSerializer())
                .addSerializer(new MapSerializer());
        HazelcastInstance hazelcastInstance = Hazelcast.getOrCreateHazelcastInstance(config);
        getLogger().info("HazelcastInstance  created... ");
        return hazelcastInstance;
    }

    public static HazelCastConfig getInstance() {
        if(hazelCastConfig==null)
            hazelCastConfig=new HazelCastConfig();
        return hazelCastConfig.isLoaded()?hazelCastConfig:hazelCastConfig.loadProperties();
    }


    public HazelCastConfig loadProperties(){
        if(!loaded) {
            String configFile = System.getenv("HAZELCAST_CONFIG_FILE");
            if (configFile == null) {
                configFile = "/media/datos/Instaladores/entalla/tomcat/conf/hazelcastConfig.xml";
                System.setProperty("HAZELCAST_CONFIG_FILE", configFile);
            }
            if (configFile != null) {
                getLogger().info("Cargando propiedades desde:" + configFile);
                if (new File(configFile).exists()) {
                    globalPropertyFile = configFile;
                    loadProperties(globalPropertyFile);
                    loaded = true;
                }
            } else {
                 getLogger().info("No se encuentra valor para la propiedad HAZELCAST_CONFIG_FILE en las variables de entorno de JVM.");
            }
        }
        return this;
    }


    public HazelCastConfig loadProperties(String configFilePath) {
        if(!loaded) {
            try {
                properties=new Properties();
                FileInputStream fis = new FileInputStream(configFilePath);
                properties.load(fis);
                instanceName = properties.getProperty("hazelcast.instance.instanceName", "softwarentalla-hazelcast-instance") ;
                classPathFileName = properties.getProperty("hazelcast.instance.classPathFileName", "alfresco/extension/hazelcastConfig.xml") ;
                // Asignar a los campos de la clase
            } catch (IOException e) {
                e.printStackTrace();  // Manejar errores adecuadamente
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            loaded = true;
        }
        return this;
    }
    public String getPropertyByKey(String key,String defaultValue){
        if(properties.containsKey(key))
            return properties.getProperty(key,defaultValue);
        return defaultValue;
    }
    public String getPropertyByKey(String key){
        if(properties.containsKey(key))
            return properties.getProperty(key,null);
        return null;
    }
    public Properties getProperties() {
        return properties;
    }

    public String getGlobalPropertyFile() {
        return globalPropertyFile;
    }


    public String extractBaseURL(String urlString) throws MalformedURLException {

        // Crear un objeto URL
        URL url = new URL(urlString);

        // Obtener el protocolo (http o https)
        String protocol = url.getProtocol();

        // Obtener el host (ses-cms.entalla.cu)
        String host = url.getHost();

        // Obtener el puerto si está definido, de lo contrario será -1
        int port = url.getPort();

        // Construir la base URL
        StringBuilder baseUrl = new StringBuilder();
        baseUrl.append(protocol).append("://").append(host);

        // Agregar el puerto si está definido
        if (port != -1) {
            baseUrl.append(":").append(port);
        }

        return baseUrl.toString();
    }


}
