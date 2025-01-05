package cu.entalla.serializer;


import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import javax.annotation.Nonnull;
import java.io.Serializable;

public class DefaultListableBeanFactorySerializer implements CompactSerializer<DefaultListableBeanFactory>, Serializable {

    @Override
    public void write(CompactWriter writer, DefaultListableBeanFactory beanFactory) {
        // Por simplicidad, solo serializamos el número de beans y sus nombres
        String[] beanDefinitionNames = beanFactory.getBeanDefinitionNames();
        writer.writeInt32("beanCount", beanDefinitionNames.length);
        writer.writeArrayOfString("beanNames", beanDefinitionNames);
    }

    @Nonnull
    @Override
    public String getTypeName() {
        return "org.springframework.beans.factory.support.DefaultListableBeanFactory";
    }

    @Override
    public DefaultListableBeanFactory read(CompactReader reader) {
        // Reconstruimos un BeanFactory vacío con las definiciones leídas
        int beanCount = reader.readInt32("beanCount");
        String[] beanNames = reader.readArrayOfString("beanNames");

        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        for (String beanName : beanNames) {
            // Puedes decidir qué hacer con cada beanName. Aquí simplemente registramos un bean genérico.
            Object bean = beanFactory.containsBean(beanName) ? beanFactory.getBean(beanName) : null;
            if(bean!=null)
            {
                beanFactory.registerSingleton(beanName, bean);
            }
        }
        return beanFactory;
    }

    @Override
    public Class<DefaultListableBeanFactory> getCompactClass() {
        return DefaultListableBeanFactory.class;
    }
}
