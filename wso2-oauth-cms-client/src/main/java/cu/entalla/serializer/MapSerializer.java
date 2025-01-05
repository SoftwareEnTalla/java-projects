package cu.entalla.serializer;


import com.hazelcast.nio.serialization.Serializer;
import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.Map;

public class MapSerializer implements CompactSerializer<Map<?extends Serializer, ?extends Serializer>> {

    @Override
    public void write(@Nonnull CompactWriter writer, @Nonnull Map<?extends Serializer, ?extends Serializer> map) {
        writer.writeInt32("size", map.size());
        int i = 0;
        for (Map.Entry<?extends Serializer, ?extends Serializer> entry : map.entrySet()) {
            writer.writeCompact("key" + i, entry.getKey());
            writer.writeCompact("value" + i, entry.getValue());
            i++;
        }
    }

    @Nonnull
    @Override
    public Map<?extends Serializer, ?extends Serializer> read(@Nonnull CompactReader reader) {
        int size = reader.readInt32("size");
        Map< Serializer, Serializer> map = new HashMap<>();
        for (int i = 0; i < size; i++) {
            Serializer key = reader.readCompact("key" + i);
            Serializer value = reader.readCompact("value" + i);
            map.put(key, value);
        }
        return map;
    }

    @Nonnull
    @Override
    public String getTypeName() {
        return "java.util.Map";
    }

    @Nonnull
    @Override
    public Class<Map<?extends Serializer, ?extends Serializer>> getCompactClass() {
        return (Class<Map<?extends Serializer, ?extends Serializer>>) (Class<?>) Map.class;
    }
}