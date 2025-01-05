//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

import java.io.IOException;

class JsonLiteral extends JsonValue {
    private final String value;

    JsonLiteral(String value) {
        this.value = value;
    }

    protected void write(JsonWriter writer) throws IOException {
        writer.write(this.value);
    }

    public String toString() {
        return this.value;
    }

    public boolean asBoolean() {
        return this.isBoolean() ? this.isTrue() : super.asBoolean();
    }

    public boolean isNull() {
        return this == NULL;
    }

    public boolean isBoolean() {
        return this == TRUE || this == FALSE;
    }

    public boolean isTrue() {
        return this == TRUE;
    }

    public boolean isFalse() {
        return this == FALSE;
    }

    public int hashCode() {
        return this.value.hashCode();
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        } else if (object == null) {
            return false;
        } else if (this.getClass() != object.getClass()) {
            return false;
        } else {
            JsonLiteral other = (JsonLiteral)object;
            return this.value.equals(other.value);
        }
    }
}
