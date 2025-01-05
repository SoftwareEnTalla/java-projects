package cu.entalla.serializer;


import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;

import javax.annotation.Nonnull;

public class ObjectSerializer implements CompactSerializer<Object> {

    @Override
    public void write(@Nonnull CompactWriter writer, @Nonnull Object obj) {
        if (obj instanceof String) {
            writer.writeString("type", "String");
            writer.writeString("value", (String) obj);
        } else if (obj instanceof Integer) {
            writer.writeString("type", "Integer");
            writer.writeInt32("value", (Integer) obj);
        } else if (obj instanceof Boolean) {
            writer.writeString("type", "Boolean");
            writer.writeBoolean("value", (Boolean) obj);
        } else {
            throw new IllegalArgumentException("Unsupported type: " + obj.getClass());
        }
    }

    @Nonnull
    @Override
    public Object read(@Nonnull CompactReader reader) {
        String type = reader.readString("type");
        switch (type) {
            case "String":
                return reader.readString("value");
            case "Integer":
                return reader.readInt32("value");
            case "Boolean":
                return reader.readBoolean("value");
            default:
                throw new IllegalArgumentException("Unsupported type: " + type);
        }
    }

    @Nonnull
    @Override
    public String getTypeName() {
        return "java.lang.Object";
    }

    @Nonnull
    @Override
    public Class<Object> getCompactClass() {
        return Object.class;
    }
}