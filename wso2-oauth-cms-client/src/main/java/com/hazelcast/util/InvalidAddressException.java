package com.hazelcast.util;

public class InvalidAddressException extends com.hazelcast.internal.util.AddressUtil.InvalidAddressException{
    public InvalidAddressException(String message) {
        super(message);
    }

    public InvalidAddressException(String message, boolean prependText) {
        super(message, prependText);
    }
}
