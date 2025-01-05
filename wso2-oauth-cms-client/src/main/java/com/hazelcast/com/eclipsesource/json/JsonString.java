//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

import java.io.IOException;

class JsonString extends JsonValue {
    private final String string;

    JsonString(String string) {
        if (string == null) {
            throw new NullPointerException("string is null");
        } else {
            this.string = string;
        }
    }

    protected void write(JsonWriter writer) throws IOException {
        writer.writeString(this.string);
    }

    public boolean isString() {
        return true;
    }

    public String asString() {
        return this.string;
    }

    public int hashCode() {
        return this.string.hashCode();
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        } else if (object == null) {
            return false;
        } else if (this.getClass() != object.getClass()) {
            return false;
        } else {
            JsonString other = (JsonString)object;
            return this.string.equals(other.string);
        }
    }
}
