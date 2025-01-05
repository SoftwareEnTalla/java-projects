package cu.entalla.serializer;


import com.hazelcast.nio.serialization.compact.CompactReader;
import com.hazelcast.nio.serialization.compact.CompactSerializer;
import com.hazelcast.nio.serialization.compact.CompactWriter;
import org.springframework.lang.NonNull;


import java.util.concurrent.atomic.AtomicBoolean;

public class AtomicBooleanSerializer implements CompactSerializer<AtomicBoolean> {

    @Override
    public void write(@NonNull CompactWriter writer, @NonNull AtomicBoolean atomicBoolean) {
        writer.writeBoolean("value", atomicBoolean.get());
    }

    @Override
    @NonNull
    public AtomicBoolean read(@NonNull CompactReader reader) {
        boolean value = reader.readBoolean("value");
        return new AtomicBoolean(value);
    }

    @Override
    @NonNull
    public String getTypeName() {
        return "java.util.concurrent.atomic.AtomicBoolean";
    }

    @Override
    @NonNull
    public Class<AtomicBoolean> getCompactClass() {
        return AtomicBoolean.class;
    }
}