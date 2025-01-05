package cu.entalla.serializer;


import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;

import javax.annotation.Nonnull;
import java.util.concurrent.atomic.AtomicBoolean;

public class AtomicBooleanSerializer implements CompactSerializer<AtomicBoolean> {

    @Override
    public void write(@Nonnull CompactWriter writer, @Nonnull AtomicBoolean atomicBoolean) {
        writer.writeBoolean("value", atomicBoolean.get());
    }

    @Override
    @Nonnull
    public AtomicBoolean read(@Nonnull CompactReader reader) {
        boolean value = reader.readBoolean("value");
        return new AtomicBoolean(value);
    }

    @Override
    @Nonnull
    public String getTypeName() {
        return "java.util.concurrent.atomic.AtomicBoolean";
    }

    @Override
    @Nonnull
    public Class<AtomicBoolean> getCompactClass() {
        return AtomicBoolean.class;
    }
}