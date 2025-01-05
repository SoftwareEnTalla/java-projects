//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.monitor;

import com.hazelcast.internal.management.JsonSerializable;

public interface LocalInstanceStats extends JsonSerializable {
    long STAT_NOT_AVAILABLE = -99L;

    long getCreationTime();
}
