//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.monitor;

public interface LocalTopicStats extends LocalInstanceStats {
    long getCreationTime();

    long getPublishOperationCount();

    long getReceiveOperationCount();
}
