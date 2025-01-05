package cu.entalla.serializer;

import com.hazelcast.nio.serialization.Serializer;
import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

public class ListSerializer implements CompactSerializer<List<?extends Serializer>> {

    @Override
    public void write(@Nonnull CompactWriter writer, @Nonnull List<? extends Serializer> list) {
        writer.writeInt32("size", list.size());
        for (int i = 0; i < list.size(); i++) {
            writer.writeCompact("element" + i, list.get(i));
        }
    }

    @Nonnull
    @Override
    public List<?extends Serializer> read(@Nonnull CompactReader reader) {
        int size = reader.readInt32("size");
        List<?extends Serializer> list = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            list.add(reader.readCompact("element" + i));
        }
        return list;
    }

    @Nonnull
    @Override
    public String getTypeName() {
        return "java.util.List";
    }

    @Nonnull
    @Override
    public Class<List<?extends Serializer>> getCompactClass() {
        return (Class<List<?extends Serializer>>) (Class<?>) List.class;
    }
}
