//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.com.eclipsesource.json;

public class ParseException extends RuntimeException {
    private final int offset;
    private final int line;
    private final int column;

    ParseException(String message, int offset, int line, int column) {
        super(message + " at " + line + ":" + column);
        this.offset = offset;
        this.line = line;
        this.column = column;
    }

    public int getOffset() {
        return this.offset;
    }

    public int getLine() {
        return this.line;
    }

    public int getColumn() {
        return this.column;
    }
}
