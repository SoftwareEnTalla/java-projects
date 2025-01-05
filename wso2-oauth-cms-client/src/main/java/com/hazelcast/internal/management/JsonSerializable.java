//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.internal.management;

import com.hazelcast.com.eclipsesource.json.JsonObject;

public interface JsonSerializable {
    JsonObject toJson();

    void fromJson(JsonObject var1);
}
