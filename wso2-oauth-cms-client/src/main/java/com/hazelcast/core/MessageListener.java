//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.core;

import java.util.EventListener;

public interface MessageListener<E> extends EventListener {
    void onMessage(Message<E> var1);
}
