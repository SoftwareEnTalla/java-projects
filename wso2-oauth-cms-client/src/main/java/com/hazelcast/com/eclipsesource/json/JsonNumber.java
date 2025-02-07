//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

import java.io.IOException;

class JsonNumber extends JsonValue {
    private final String string;

    JsonNumber(String string) {
        if (string == null) {
            throw new NullPointerException("string is null");
        } else {
            this.string = string;
        }
    }

    public String toString() {
        return this.string;
    }

    protected void write(JsonWriter writer) throws IOException {
        writer.write(this.string);
    }

    public boolean isNumber() {
        return true;
    }

    public int asInt() {
        return Integer.parseInt(this.string, 10);
    }

    public long asLong() {
        return Long.parseLong(this.string, 10);
    }

    public float asFloat() {
        return Float.parseFloat(this.string);
    }

    public double asDouble() {
        return Double.parseDouble(this.string);
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
            JsonNumber other = (JsonNumber)object;
            return this.string.equals(other.string);
        }
    }
}
