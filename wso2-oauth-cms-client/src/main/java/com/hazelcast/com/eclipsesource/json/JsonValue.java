//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

import java.io.IOException;
import java.io.Reader;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.Writer;

public abstract class JsonValue implements Serializable {
    public static final JsonValue TRUE = new JsonLiteral("true");
    public static final JsonValue FALSE = new JsonLiteral("false");
    public static final JsonValue NULL = new JsonLiteral("null");

    JsonValue() {
    }

    public static JsonValue readFrom(Reader reader) throws IOException {
        return (new JsonParser(reader)).parse();
    }

    public static JsonValue readFrom(String text) {
        try {
            return (new JsonParser(text)).parse();
        } catch (IOException var2) {
            throw new RuntimeException(var2);
        }
    }

    public static JsonValue valueOf(int value) {
        return new JsonNumber(Integer.toString(value, 10));
    }

    public static JsonValue valueOf(long value) {
        return new JsonNumber(Long.toString(value, 10));
    }

    public static JsonValue valueOf(float value) {
        if (!Float.isInfinite(value) && !Float.isNaN(value)) {
            return new JsonNumber(cutOffPointZero(Float.toString(value)));
        } else {
            throw new IllegalArgumentException("Infinite and NaN values not permitted in JSON");
        }
    }

    public static JsonValue valueOf(double value) {
        if (!Double.isInfinite(value) && !Double.isNaN(value)) {
            return new JsonNumber(cutOffPointZero(Double.toString(value)));
        } else {
            throw new IllegalArgumentException("Infinite and NaN values not permitted in JSON");
        }
    }

    public static JsonValue valueOf(String string) {
        return (JsonValue)(string == null ? NULL : new JsonString(string));
    }

    public static JsonValue valueOf(boolean value) {
        return value ? TRUE : FALSE;
    }

    public boolean isObject() {
        return false;
    }

    public boolean isArray() {
        return false;
    }

    public boolean isNumber() {
        return false;
    }

    public boolean isString() {
        return false;
    }

    public boolean isBoolean() {
        return false;
    }

    public boolean isTrue() {
        return false;
    }

    public boolean isFalse() {
        return false;
    }

    public boolean isNull() {
        return false;
    }

    public JsonObject asObject() {
        throw new UnsupportedOperationException("Not an object: " + this.toString());
    }

    public JsonArray asArray() {
        throw new UnsupportedOperationException("Not an array: " + this.toString());
    }

    public int asInt() {
        throw new UnsupportedOperationException("Not a number: " + this.toString());
    }

    public long asLong() {
        throw new UnsupportedOperationException("Not a number: " + this.toString());
    }

    public float asFloat() {
        throw new UnsupportedOperationException("Not a number: " + this.toString());
    }

    public double asDouble() {
        throw new UnsupportedOperationException("Not a number: " + this.toString());
    }

    public String asString() {
        throw new UnsupportedOperationException("Not a string: " + this.toString());
    }

    public boolean asBoolean() {
        throw new UnsupportedOperationException("Not a boolean: " + this.toString());
    }

    public void writeTo(Writer writer) throws IOException {
        this.write(new JsonWriter(writer));
    }

    public String toString() {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = new JsonWriter(stringWriter);

        try {
            this.write(jsonWriter);
        } catch (IOException var4) {
            throw new RuntimeException(var4);
        }

        return stringWriter.toString();
    }

    public boolean equals(Object object) {
        return super.equals(object);
    }

    public int hashCode() {
        return super.hashCode();
    }

    protected abstract void write(JsonWriter var1) throws IOException;

    private static String cutOffPointZero(String string) {
        return string.endsWith(".0") ? string.substring(0, string.length() - 2) : string;
    }
}
