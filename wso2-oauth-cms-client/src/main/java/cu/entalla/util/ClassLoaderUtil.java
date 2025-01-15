package cu.entalla.util;

import cu.entalla.udi.ClientServiceIntegration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.logging.Logger;

public class ClassLoaderUtil {

    private static final Logger logger = Logger.getLogger(ClassLoaderUtil.class.getName());
    public static  Class<?> loadClassDynamically(String className) {
        try {
            // Intenta cargar la clase
            Class<?> clazz = Class.forName(className);
            logger.info("Clase "+className+" encontrada: " + clazz.getName());
            return clazz;
        } catch (ClassNotFoundException e) {
            // Manejo si la clase no existe en el classpath
            logger.info("La clase " + className + " no existe en el classpath.");
            return null;
        }
    }

    public static ClientServiceIntegration loadDynamicBean(ApplicationContext context, String className) {
        try {
            // Carga dinámica de la clase
            Class<?> clazz = Class.forName(className);
            // Verifica si la clase implementa ClientServiceIntegration
            if (!ClientServiceIntegration.class.isAssignableFrom(clazz)) {
                throw new IllegalArgumentException("La clase " + className + " no implementa ClientServiceIntegration");
            }

            // Comprueba si el bean ya existe en el contexto
            String[] beanNames = context.getBeanNamesForType(clazz);
            if (beanNames.length > 0) {
                // Devuelve el bean existente
                return (ClientServiceIntegration) context.getBean(clazz);
            }

            // Registra la clase como un nuevo bean
            ConfigurableApplicationContext configurableContext = (ConfigurableApplicationContext) context;
            Object instance = clazz.getDeclaredConstructor().newInstance();
            configurableContext.getBeanFactory().registerSingleton(className, instance);

            // Devuelve la instancia del bean registrado
            return (ClientServiceIntegration) instance;
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Clase no encontrada: " + className, e);
        } catch (Exception e) {
            throw new RuntimeException("Error cargando dinámicamente el bean: " + className, e);
        }
    }
    public static ClientServiceIntegration loadDynamicBean(ApplicationContext context, String className,Class<?> clase) {
        try {
            // Carga dinámica de la clase
            Class<?> clazz = Class.forName(className);
            // Verifica si la clase implementa ClientServiceIntegration
            if (!clase.isAssignableFrom(clazz)) {
                throw new IllegalArgumentException("La clase " + className + " no implementa ClientServiceIntegration");
            }

            // Comprueba si el bean ya existe en el contexto
            String[] beanNames = context.getBeanNamesForType(clazz);
            if (beanNames.length > 0) {
                // Devuelve el bean existente
                return (ClientServiceIntegration) context.getBean(clazz);
            }

            // Registra la clase como un nuevo bean
            ConfigurableApplicationContext configurableContext = (ConfigurableApplicationContext) context;
            Object instance = clazz.getDeclaredConstructor().newInstance();
            configurableContext.getBeanFactory().registerSingleton(className, instance);

            // Devuelve la instancia del bean registrado
            return (ClientServiceIntegration) instance;
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Clase no encontrada: " + className, e);
        } catch (Exception e) {
            throw new RuntimeException("Error cargando dinámicamente el bean: " + className, e);
        }
    }


}
