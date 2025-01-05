//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.core;

import com.hazelcast.nio.Address;
import com.hazelcast.nio.serialization.DataSerializable;
import java.net.InetSocketAddress;
import java.util.Map;

public interface Member extends DataSerializable, Endpoint {
    boolean localMember();

    boolean isLiteMember();

    Address getAddress();

    /** @deprecated */
    @Deprecated
    InetSocketAddress getInetSocketAddress();

    InetSocketAddress getSocketAddress();

    String getUuid();

    Map<String, Object> getAttributes();

    String getStringAttribute(String var1);

    void setStringAttribute(String var1, String var2);

    Boolean getBooleanAttribute(String var1);

    void setBooleanAttribute(String var1, boolean var2);

    Byte getByteAttribute(String var1);

    void setByteAttribute(String var1, byte var2);

    Short getShortAttribute(String var1);

    void setShortAttribute(String var1, short var2);

    Integer getIntAttribute(String var1);

    void setIntAttribute(String var1, int var2);

    Long getLongAttribute(String var1);

    void setLongAttribute(String var1, long var2);

    Float getFloatAttribute(String var1);

    void setFloatAttribute(String var1, float var2);

    Double getDoubleAttribute(String var1);

    void setDoubleAttribute(String var1, double var2);

    void removeAttribute(String var1);
}
