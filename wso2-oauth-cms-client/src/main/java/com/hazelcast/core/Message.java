//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.core;

import java.util.EventObject;

public class Message<E> extends EventObject {
    protected E messageObject;
    private final long publishTime;
    private final Member publishingMember;

    public Message(String topicName, E messageObject, long publishTime, Member publishingMember) {
        super(topicName);
        this.messageObject = messageObject;
        this.publishTime = publishTime;
        this.publishingMember = publishingMember;
    }

    public E getMessageObject() {
        return this.messageObject;
    }

    public long getPublishTime() {
        return this.publishTime;
    }

    public Member getPublishingMember() {
        return this.publishingMember;
    }
}
