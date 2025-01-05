//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class JsonObject extends JsonValue implements Iterable<JsonObject.Member> {
    private final List<String> names;
    private final List<JsonValue> values;
    private transient HashIndexTable table;

    public JsonObject() {
        this.names = new ArrayList();
        this.values = new ArrayList();
        this.table = new HashIndexTable();
    }

    public JsonObject(JsonObject object) {
        this(object, false);
    }

    private JsonObject(JsonObject object, boolean unmodifiable) {
        if (object == null) {
            throw new NullPointerException("object is null");
        } else {
            if (unmodifiable) {
                this.names = Collections.unmodifiableList(object.names);
                this.values = Collections.unmodifiableList(object.values);
            } else {
                this.names = new ArrayList(object.names);
                this.values = new ArrayList(object.values);
            }

            this.table = new HashIndexTable();
            this.updateHashIndex();
        }
    }

    public static JsonObject readFrom(Reader reader) throws IOException {
        return JsonValue.readFrom(reader).asObject();
    }

    public static JsonObject readFrom(String string) {
        return JsonValue.readFrom(string).asObject();
    }

    public static JsonObject unmodifiableObject(JsonObject object) {
        return new JsonObject(object, true);
    }

    public JsonObject add(String name, int value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, long value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, float value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, double value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, boolean value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, String value) {
        this.add(name, valueOf(value));
        return this;
    }

    public JsonObject add(String name, JsonValue value) {
        if (name == null) {
            throw new NullPointerException("name is null");
        } else if (value == null) {
            throw new NullPointerException("value is null");
        } else {
            this.table.add(name, this.names.size());
            this.names.add(name);
            this.values.add(value);
            return this;
        }
    }

    public JsonObject set(String name, int value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, long value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, float value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, double value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, boolean value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, String value) {
        this.set(name, valueOf(value));
        return this;
    }

    public JsonObject set(String name, JsonValue value) {
        if (name == null) {
            throw new NullPointerException("name is null");
        } else if (value == null) {
            throw new NullPointerException("value is null");
        } else {
            int index = this.indexOf(name);
            if (index != -1) {
                this.values.set(index, value);
            } else {
                this.table.add(name, this.names.size());
                this.names.add(name);
                this.values.add(value);
            }

            return this;
        }
    }

    public JsonObject remove(String name) {
        if (name == null) {
            throw new NullPointerException("name is null");
        } else {
            int index = this.indexOf(name);
            if (index != -1) {
                this.table.remove(index);
                this.names.remove(index);
                this.values.remove(index);
            }

            return this;
        }
    }

    public JsonValue get(String name) {
        if (name == null) {
            throw new NullPointerException("name is null");
        } else {
            int index = this.indexOf(name);
            return index != -1 ? (JsonValue)this.values.get(index) : null;
        }
    }

    public int getInt(String name, int defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asInt() : defaultValue;
    }

    public long getLong(String name, long defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asLong() : defaultValue;
    }

    public float getFloat(String name, float defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asFloat() : defaultValue;
    }

    public double getDouble(String name, double defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asDouble() : defaultValue;
    }

    public boolean getBoolean(String name, boolean defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asBoolean() : defaultValue;
    }

    public String getString(String name, String defaultValue) {
        JsonValue value = this.get(name);
        return value != null ? value.asString() : defaultValue;
    }

    public int size() {
        return this.names.size();
    }

    public boolean isEmpty() {
        return this.names.isEmpty();
    }

    public List<String> names() {
        return Collections.unmodifiableList(this.names);
    }

    public Iterator<Member> iterator() {
        final Iterator<String> namesIterator = this.names.iterator();
        final Iterator<JsonValue> valuesIterator = this.values.iterator();
        return new Iterator<Member>() {
            public boolean hasNext() {
                return namesIterator.hasNext();
            }

            public Member next() {
                String name = (String)namesIterator.next();
                JsonValue value = (JsonValue)valuesIterator.next();
                return new Member(name, value);
            }

            public void remove() {
                throw new UnsupportedOperationException();
            }
        };
    }

    protected void write(JsonWriter writer) throws IOException {
        writer.writeObject(this);
    }

    public boolean isObject() {
        return true;
    }

    public JsonObject asObject() {
        return this;
    }

    public int hashCode() {
        int result = 1;
        result = 31 * result + this.names.hashCode();
        result = 31 * result + this.values.hashCode();
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj == null) {
            return false;
        } else if (this.getClass() != obj.getClass()) {
            return false;
        } else {
            JsonObject other = (JsonObject)obj;
            return this.names.equals(other.names) && this.values.equals(other.values);
        }
    }

    int indexOf(String name) {
        int index = this.table.get(name);
        return index != -1 && name.equals(this.names.get(index)) ? index : this.names.lastIndexOf(name);
    }

    private synchronized void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();
        this.table = new HashIndexTable();
        this.updateHashIndex();
    }

    private void updateHashIndex() {
        int size = this.names.size();

        for(int i = 0; i < size; ++i) {
            this.table.add((String)this.names.get(i), i);
        }

    }

    static class HashIndexTable {
        private final byte[] hashTable = new byte[32];

        public HashIndexTable() {
        }

        public HashIndexTable(HashIndexTable original) {
            System.arraycopy(original.hashTable, 0, this.hashTable, 0, this.hashTable.length);
        }

        void add(String name, int index) {
            int slot = this.hashSlotFor(name);
            if (index < 255) {
                this.hashTable[slot] = (byte)(index + 1);
            } else {
                this.hashTable[slot] = 0;
            }

        }

        void remove(int index) {
            for(int i = 0; i < this.hashTable.length; ++i) {
                if (this.hashTable[i] == index + 1) {
                    this.hashTable[i] = 0;
                } else if (this.hashTable[i] > index + 1) {
                    --this.hashTable[i];
                }
            }

        }

        int get(Object name) {
            int slot = this.hashSlotFor(name);
            return (this.hashTable[slot] & 255) - 1;
        }

        private int hashSlotFor(Object element) {
            return element.hashCode() & this.hashTable.length - 1;
        }
    }

    public static class Member {
        private final String name;
        private final JsonValue value;

        Member(String name, JsonValue value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return this.name;
        }

        public JsonValue getValue() {
            return this.value;
        }

        public int hashCode() {
            int result = 1;
            result = 31 * result + this.name.hashCode();
            result = 31 * result + this.value.hashCode();
            return result;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            } else if (obj == null) {
                return false;
            } else if (this.getClass() != obj.getClass()) {
                return false;
            } else {
                Member other = (Member)obj;
                return this.name.equals(other.name) && this.value.equals(other.value);
            }
        }
    }
}
