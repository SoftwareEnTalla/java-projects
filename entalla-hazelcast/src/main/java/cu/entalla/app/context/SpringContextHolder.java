package cu.entalla.app.context;

import com.hazelcast.core.HazelcastInstance;
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

public class SpringContextHolder  {
    private static ApplicationContext context;

    private static HazelcastInstance hazelcastInstance;
    private static IMap<String, ApplicationContext> contextRegistry;

    private static IMap<String, Class<? extends Serializer>> globalRegistry;

    private static final Log logger = LogFactory.getLog(ApplicationContext.class);
    public static void setApplicationContext(String contextName, ApplicationContext context) throws Exception {
        if (contextName == null || context == null) {
            throw new Exception("El nombre o el contexto no pueden ser null.");
        }
        if(contextRegistry==null)
             contextRegistry =hazelcastClassPathInstance().getMap("contextRegistry");
        contextRegistry.put(contextName, context);
        logger.info("Contexto registrado: " + contextName);
    }

    public static void setApplicationContext(String hazelCastInstanceName,String hazelCastConfigFile, String contextName, ApplicationContext context) throws Exception {
        if (contextName == null || context == null) {
            throw new Exception("El nombre o el contexto no pueden ser null.");
        }
        if(contextRegistry==null)
            contextRegistry =hazelcastFromFileInstance(hazelCastInstanceName,hazelCastConfigFile).getMap("contextRegistry");
        contextRegistry.put(contextName, context);
        logger.info("Contexto registrado: " + contextName);
    }

    public static   IMap<String, ApplicationContext> getContextRegistry(){
        return contextRegistry;
    }

    public static   IMap<String, Class<? extends com.hazelcast.nio.serialization.Serializer>> getGlobalRegistry(){
        return globalRegistry=hazelcastClassPathInstance().getMap("globalRegistry");
    }
    public static   IMap<String, Class<? extends com.hazelcast.nio.serialization.Serializer>> getGlobalRegistry(String instanceName,String fileConfig) throws FileNotFoundException {
        return globalRegistry=hazelcastFromFileInstance(instanceName,fileConfig).getMap("globalRegistry");
    }
    public static   IMap<String, Class<? extends com.hazelcast.nio.serialization.Serializer>> registry(String key,Class<? extends com.hazelcast.nio.serialization.Serializer> value){
        globalRegistry = getGlobalRegistry();
        globalRegistry.put(key,value);
        return globalRegistry;
    }
    public static HazelcastInstance hazelcastClassPathInstance(){
        if(hazelcastInstance==null){
            HazelCastConfig segConfig= HazelCastConfig.getInstance();
            hazelcastInstance = segConfig.hazelcastClassPathInstance();// Hazelcast.newHazelcastInstance();
            contextRegistry = hazelcastInstance.getMap("contextRegistry");
            getGlobalRegistry();
        }
        //hazelcastInstance.addDistributedObjectListener(new AddDistributedObjectListenerMessageTask())
        return hazelcastInstance;
    }
    public static HazelcastInstance hazelcastFromFileInstance(String name,String file) throws FileNotFoundException {
        if(hazelcastInstance==null){
            HazelCastConfig segConfig= HazelCastConfig.getInstance();
            hazelcastInstance = segConfig.hazelcastFromFileInstance(name,file);// Hazelcast.newHazelcastInstance();
            contextRegistry = hazelcastInstance.getMap("contextRegistry");
            getGlobalRegistry();
        }
        //hazelcastInstance.addDistributedObjectListener(new AddDistributedObjectListenerMessageTask())
        return hazelcastInstance;
    }

    public static ConfigService loadShareConfiguration(ApplicationContext alfrescoContext,String filePath) {
        ConfigService configService = alfrescoContext.getBean("web.config", ConfigService.class);
        try {
            File shareConfigFile = new File(filePath);
            if (shareConfigFile.exists()) {
                configService.appendConfig(new ClassPathConfigSource(Arrays.asList(
                        "alfresco/web-extension",  // Ruta típica de configuraciones de Alfresco Share
                        "alfresco/extension"       // Ruta típica para configuraciones personalizadas
                )));
                configService.appendConfig(new FileConfigSource(filePath));
               logger.info("Loaded "+filePath+" into Alfresco context.");
            } else {
                logger.warn(filePath+" not found.");
            }
        } catch (Exception e) {
            logger.error("Error loading "+filePath+": ", e);
        }
        return configService;
    }
    public static ApplicationContext getApplicationContext(String contextName){
        if(contextRegistry==null)
            contextRegistry=hazelcastClassPathInstance().getMap("contextRegistry");
        return contextRegistry!=null && contextRegistry.containsKey(contextName)? contextRegistry.get(contextName):null;
    }
    public static void registry(String contextName,ApplicationContext context) throws Exception {
        if(contextName==null)
            throw new Exception("La clave de registro del contexto no puede ser null.");
        if(context==null)
             throw new Exception("El contexto no puede ser null.");
        logger.error(":::::::::::::::::::::::: Se registra el Contexto para "+contextName+" de forma satisfactoria ::::::::::::::::::::::::");
        logger.error(":::::::::::::::::::::::: Se registra el Contexto para la aplicación:"+context.getApplicationName()+" de forma satisfactoria ::::::::::::::::::::::::");
        contextRegistry.putIfAbsent(contextName,context);
    }

    public static <T> T getBean(Class<T> requiredType) {

        try {
            return context!=null?context.getBean(requiredType):null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+requiredType+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static <T> T getBean(String name,Class<T> requiredType) {

        try {
            return context!=null?context.getBean(name,requiredType):null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+name+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static <T> T getBean(Class<T> requiredType,Object... args) {

        try {
            return context!=null?context.getBean(requiredType,args) :null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+requiredType+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static Object getBean(String name) {
        try {
            return context != null ? context.getBean(name) : null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+name+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static Object getBean(String name,Object... args) {

        try {
            return context!=null?context.getBean(name,args) :null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+name+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static Object getBean(ApplicationContext appContext,String name,Object... args) {

        try {
            return appContext!=null?appContext.getBean(name,args) :null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+name+"\nDesciption:"+be.getMessage());
        }
        return null;
    }
    public static Object getBean(String contextName,String name,Object... args) {

        try {
            ApplicationContext appContext=getApplicationContext(contextName);
            return appContext!=null?appContext.getBean(name,args) :null;
        }
        catch (BeansException be){
            logger.error("Error al devolver el Bean:"+name+"\nDesciption:"+be.getMessage());
        }
        return null;
    }


}
