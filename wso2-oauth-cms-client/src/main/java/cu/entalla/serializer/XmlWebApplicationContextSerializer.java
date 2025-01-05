package cu.entalla.serializer;

import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.annotation.Nonnull;

public class XmlWebApplicationContextSerializer implements CompactSerializer<XmlWebApplicationContext> {

    @Override
    public void write(@Nonnull CompactWriter writer, @Nonnull XmlWebApplicationContext context) {
        // Serializar solo campos esenciales del contexto
        writer.writeString("id", context.getId());
        writer.writeString("displayName", context.getDisplayName());
        writer.writeString("applicationName", context.getApplicationName());
        writer.writeString("configLocation", String.join(" ",context.getConfigLocations()));

        // No serializar el Thread u otros campos no relevantes
    }

    @Nonnull
    @Override
    public XmlWebApplicationContext read(@Nonnull CompactReader reader) {
        // Reconstruir el objeto XmlWebApplicationContext con los datos esenciales
        XmlWebApplicationContext context = new XmlWebApplicationContext();
        context.setId(reader.readString("id"));
        context.setDisplayName(reader.readString("displayName"));
        context.setConfigLocation(reader.readString("configLocation"));
        // Nota: Los campos no serializados, como Thread, deben configurarse manualmente si son necesarios
        return context;
    }

    @Nonnull
    @Override
    public String getTypeName() {
        return "org.springframework.web.context.support.XmlWebApplicationContext";
    }

    @Nonnull
    @Override
    public Class<XmlWebApplicationContext> getCompactClass() {
        return XmlWebApplicationContext.class;
    }
}