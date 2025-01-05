//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.util;

import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public final class StringUtil {
    public static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
    public static final String LINE_SEPARATOR = System.getProperty("line.separator");
    public static final Locale LOCALE_INTERNAL;

    private StringUtil() {
    }

    public static String bytesToString(byte[] bytes, int offset, int length) {
        return new String(bytes, offset, length, UTF8_CHARSET);
    }

    public static String bytesToString(byte[] bytes) {
        return new String(bytes, UTF8_CHARSET);
    }

    public static byte[] stringToBytes(String s) {
        return s.getBytes(UTF8_CHARSET);
    }

    public static boolean isNullOrEmpty(String s) {
        return s == null ? true : s.isEmpty();
    }

    public static boolean isNullOrEmptyAfterTrim(String s) {
        return s == null ? true : s.trim().isEmpty();
    }

    public static String upperCaseInternal(String s) {
        return isNullOrEmpty(s) ? s : s.toUpperCase(LOCALE_INTERNAL);
    }

    public static String lowerCaseInternal(String s) {
        return isNullOrEmpty(s) ? s : s.toLowerCase(LOCALE_INTERNAL);
    }

    public static String timeToString(long timeMillis) {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        return dateFormat.format(new Date(timeMillis));
    }

    public static String timeToStringFriendly(long timeMillis) {
        return timeMillis == 0L ? "never" : timeToString(timeMillis);
    }

    public static int indexOf(String input, char ch, int offset) {
        for(int i = offset; i < input.length(); ++i) {
            if (input.charAt(i) == ch) {
                return i;
            }
        }

        return -1;
    }

    public static int indexOf(String input, char ch) {
        return indexOf(input, ch, 0);
    }

    public static int lastIndexOf(String input, char ch, int offset) {
        for(int i = input.length() - 1 - offset; i >= 0; --i) {
            if (input.charAt(i) == ch) {
                return i;
            }
        }

        return -1;
    }

    public static int lastIndexOf(String input, char ch) {
        return lastIndexOf(input, ch, 0);
    }

    static {
        LOCALE_INTERNAL = Locale.US;
    }
}
