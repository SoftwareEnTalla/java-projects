//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.core;

import com.hazelcast.monitor.LocalTopicStats;

public interface ITopic<E> extends com.hazelcast.topic.ITopic {
    String getName();

    //void publish(E var1);

    String addMessageListener(MessageListener<E> var1);

    boolean removeMessageListener(String var1);

    //LocalTopicStats getLocalTopicStats();
}
