package cu.entalla.app.context;

import com.hazelcast.client.impl.protocol.task.AddDistributedObjectListenerMessageTask;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.LifecycleEvent;
import com.hazelcast.map.IMap;
import com.hazelcast.nio.serialization.Serializer;
import cu.entalla.config.HazelCastConfig;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.source.ClassPathConfigSource;
import org.springframework.extensions.config.source.FileConfigSource;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SpringContextHolder {
    private static ApplicationContext context;
    private static HazelcastInstance hazelcastInstance;
    private static IMap<String, ApplicationContext> contextRegistryHazelcast;
    private static IMap<String, Class<? extends Serializer>> globalRegistryHazelcast;
    private static Map<String, ApplicationContext> contextRegistryHashMap = new HashMap<>();
    private static Map<String, Class<? extends Serializer>> globalRegistryHashMap = new HashMap<>();

    private static final Log logger = LogFactory.getLog(SpringContextHolder.class);

    private static String registryMode = "default"; // Valores posibles: "default" o "cluster"

    public static void setRegistryMode(String mode) {
        if (!mode.equals("default") && !mode.equals("cluster")) {
            throw new IllegalArgumentException("El modo debe ser 'default' o 'cluster'.");
        }
        registryMode = mode;
    }

    public static void setApplicationContext(String contextName, ApplicationContext applicationContext) throws Exception {
        if (contextName == null || applicationContext == null) {
            throw new Exception("El nombre o el contexto no pueden ser null.");
        }

        if (registryMode.equals("default")) {
            contextRegistryHashMap.put(contextName, applicationContext);
        } else {
            if (contextRegistryHazelcast == null) {
                initializeHazelcastContextRegistry();
            }
            contextRegistryHazelcast.put(contextName, applicationContext);
        }
        logger.info("Contexto registrado: " + contextName);
    }

    public static IMap<String, ApplicationContext> getContextRegistryHazelcast() {
        if (contextRegistryHazelcast == null) {
            initializeHazelcastContextRegistry();
        }
        return contextRegistryHazelcast;
    }

    public static Map<String, ApplicationContext> getContextRegistryHashMap() {
        return contextRegistryHashMap;
    }

    public static Map<String, Class<? extends Serializer>> getGlobalRegistryHashMap() {
        return globalRegistryHashMap;
    }

    public static IMap<String, Class<? extends Serializer>> getGlobalRegistryHazelcast() {
        if (globalRegistryHazelcast == null) {
            initializeHazelcastGlobalRegistry();
        }
        return globalRegistryHazelcast;
    }

    public static Object getBean(String contextName, String beanName) {
        ApplicationContext appContext = registryMode.equals("default") ?
                contextRegistryHashMap.get(contextName) :
                getContextRegistryHazelcast().get(contextName);
        if (appContext != null) {
            return appContext.getBean(beanName);
        }
        return null;
    }

    public static   IMap<String, Class<? extends com.hazelcast.nio.serialization.Serializer>> getGlobalRegistry(){
        return globalRegistryHazelcast=hazelcastClassPathInstance().getMap("globalRegistry");
    }
    public static   IMap<String, Class<? extends com.hazelcast.nio.serialization.Serializer>> getGlobalRegistry(String instanceName,String fileConfig) throws FileNotFoundException {
        return globalRegistryHazelcast=hazelcastFromFileInstance(instanceName,fileConfig).getMap("globalRegistry");
    }
    public static HazelcastInstance hazelcastClassPathInstance(){
        if(hazelcastInstance==null){
            logger.error(":::::::::::::::::::::::: Se comienza a inicializar instancia de HazelCast ::::::::::::::::::::::::");
            HazelCastConfig segConfig= HazelCastConfig.getInstance();
            hazelcastInstance = segConfig.hazelcastClassPathInstance();// Hazelcast.newHazelcastInstance();
            contextRegistryHazelcast = hazelcastInstance.getMap("contextRegistry");
            getGlobalRegistry();
        }
        //hazelcastInstance.addDistributedObjectListener(new AddDistributedObjectListenerMessageTask())
        return hazelcastInstance;
    }
    public static HazelcastInstance hazelcastFromFileInstance(String name,String file) throws FileNotFoundException {
        if(hazelcastInstance==null){
            logger.error(":::::::::::::::::::::::: Se comienza a inicializar instancia de HazelCast:"+name+" ::::::::::::::::::::::::");
            HazelCastConfig segConfig= HazelCastConfig.getInstance();
            hazelcastInstance = segConfig.hazelcastFromFileInstance(name,file);// Hazelcast.newHazelcastInstance();
            contextRegistryHazelcast = hazelcastInstance.getMap("contextRegistry");
            getGlobalRegistry();
        }
        //hazelcastInstance.addDistributedObjectListener(new AddDistributedObjectListenerMessageTask());
        return hazelcastInstance;
    }
    private static void initializeHazelcastContextRegistry() {
        logger.error(":::::::::::::::::::::::: Se comienza a inicializar instancia de HazelCast ::::::::::::::::::::::::");
        HazelCastConfig segConfig = HazelCastConfig.getInstance();
        hazelcastInstance = segConfig.hazelcastClassPathInstance();
        hazelcastInstance.getLifecycleService().addLifecycleListener(event -> {
            if (event.getState() == LifecycleEvent.LifecycleState.SHUTTING_DOWN) {
                hazelcastInstance.shutdown();
            }
        });
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Apagando la JVM. Cerrando Hazelcast...");
            hazelcastInstance.shutdown();
        }));
        contextRegistryHazelcast = hazelcastInstance.getMap("contextRegistry");
    }

    private static void initializeHazelcastGlobalRegistry() {
        if (hazelcastInstance == null) {
            initializeHazelcastContextRegistry();
        }
       globalRegistryHazelcast = hazelcastInstance.getMap("globalRegistry");
    }

    public static void registry(String key, Class<? extends Serializer> value) {
        if (registryMode.equals("default")) {
            globalRegistryHashMap.put(key, value);
        } else {
            if (globalRegistryHazelcast == null) {
                initializeHazelcastGlobalRegistry();
            }
            globalRegistryHazelcast.put(key, value);
        }
    }

    public static ApplicationContext getApplicationContext(String contextName) {
        return registryMode.equals("default") ?
                contextRegistryHashMap.get(contextName) :
                getContextRegistryHazelcast().get(contextName);
    }

    public static ConfigService loadShareConfiguration(ApplicationContext context, String filePath) {
        ConfigService configService = context.getBean("web.config", ConfigService.class);
        try {
            File shareConfigFile = new File(filePath);
            if (shareConfigFile.exists()) {
                configService.appendConfig(new ClassPathConfigSource(Arrays.asList(
                        "alfresco/web-extension",
                        "alfresco/extension"
                )));
                configService.appendConfig(new FileConfigSource(filePath));
                logger.info("Loaded " + filePath + " into context.");
            } else {
                logger.warn(filePath + " not found.");
            }
        } catch (Exception e) {
            logger.error("Error loading " + filePath + ": ", e);
        }
        return configService;
    }

    public static <T> T getBean(Class<T> requiredType) {
        try {
            return context != null ? context.getBean(requiredType) : null;
        } catch (BeansException be) {
            logger.error("Error al devolver el Bean:" + requiredType + "\nDescripcion:" + be.getMessage());
        }
        return null;
    }
}
