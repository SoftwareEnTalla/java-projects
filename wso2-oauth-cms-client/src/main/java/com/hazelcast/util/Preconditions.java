//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.util;

import java.util.Iterator;
import java.util.NoSuchElementException;

public final class Preconditions {
    private Preconditions() {
    }

    public static String checkHasText(String argument, String errorMessage) {
        if (argument != null && !argument.isEmpty()) {
            return argument;
        } else {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    public static <T> T checkNotNull(T argument, String errorMessage) {
        if (argument == null) {
            throw new NullPointerException(errorMessage);
        } else {
            return argument;
        }
    }

    public static <T> T checkNotNull(T argument) {
        if (argument == null) {
            throw new NullPointerException();
        } else {
            return argument;
        }
    }

    public static <E> E isNotNull(E argument, String argName) {
        if (argument == null) {
            throw new IllegalArgumentException(String.format("argument '%s' can't be null", argName));
        } else {
            return argument;
        }
    }

    public static long checkNotNegative(long value, String errorMessage) {
        if (value < 0L) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return value;
        }
    }

    public static int checkNotNegative(int value, String errorMessage) {
        if (value < 0) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return value;
        }
    }

    public static long checkNegative(long value, String errorMessage) {
        if (value >= 0L) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return value;
        }
    }

    public static long checkPositive(long value, String errorMessage) {
        if (value <= 0L) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return value;
        }
    }

    public static int checkPositive(int value, String errorMessage) {
        if (value <= 0) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return value;
        }
    }

    public static int checkBackupCount(int newBackupCount, int currentAsyncBackupCount) {
        if (newBackupCount < 0) {
            throw new IllegalArgumentException("backup-count can't be smaller than 0");
        } else if (currentAsyncBackupCount < 0) {
            throw new IllegalArgumentException("async-backup-count can't be smaller than 0");
        } else if (newBackupCount > 6) {
            throw new IllegalArgumentException("backup-count can't be larger than than 6");
        } else if (newBackupCount + currentAsyncBackupCount > 6) {
            throw new IllegalArgumentException("the sum of backup-count and async-backup-count can't be larger than than 6");
        } else {
            return newBackupCount;
        }
    }

    public static int checkAsyncBackupCount(int currentBackupCount, int newAsyncBackupCount) {
        if (currentBackupCount < 0) {
            throw new IllegalArgumentException("backup-count can't be smaller than 0");
        } else if (newAsyncBackupCount < 0) {
            throw new IllegalArgumentException("async-backup-count can't be smaller than 0");
        } else if (newAsyncBackupCount > 6) {
            throw new IllegalArgumentException("async-backup-count can't be larger than than 6");
        } else if (currentBackupCount + newAsyncBackupCount > 6) {
            throw new IllegalArgumentException("the sum of backup-count and async-backup-count can't be larger than than 6");
        } else {
            return newAsyncBackupCount;
        }
    }

    public static <E> E checkInstanceOf(Class type, E object, String errorMessage) {
        isNotNull(type, "type");
        if (!type.isInstance(object)) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return object;
        }
    }

    public static <E> E checkNotInstanceOf(Class type, E object, String errorMessage) {
        isNotNull(type, "type");
        if (type.isInstance(object)) {
            throw new IllegalArgumentException(errorMessage);
        } else {
            return object;
        }
    }

    public static void checkFalse(boolean expression, String errorMessage) {
        if (expression) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    public static void checkTrue(boolean expression, String errorMessage) {
        if (!expression) {
            throw new IllegalArgumentException(errorMessage);
        }
    }

    public static <T> Iterator<T> checkHasNext(Iterator<T> iterator, String message) throws NoSuchElementException {
        if (!iterator.hasNext()) {
            throw new NoSuchElementException(message);
        } else {
            return iterator;
        }
    }

    public static void checkState(boolean condition, String message) throws IllegalStateException {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
