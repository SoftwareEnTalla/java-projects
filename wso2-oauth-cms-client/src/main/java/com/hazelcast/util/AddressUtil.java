//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hazelcast.util;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;

public final class AddressUtil {
    private static final int NUMBER_OF_ADDRESSES = 255;
    private static final int IPV4_LENGTH = 4;
    private static final int IPV6_LENGTH = 8;
    private static final int IPV6_MAX_THRESHOLD = 65535;
    private static final int IPV4_MAX_THRESHOLD = 255;
    private static final int HEXADECIMAL_RADIX = 16;
    private static final int DECIMAL_RADIX = 10;

    private AddressUtil() {
    }

    public static boolean matchAnyInterface(String address, Collection<String> interfaces) {
        if (interfaces != null && interfaces.size() != 0) {
            Iterator var2 = interfaces.iterator();

            String interfaceMask;
            do {
                if (!var2.hasNext()) {
                    return false;
                }

                interfaceMask = (String)var2.next();
            } while(!matchInterface(address, interfaceMask));

            return true;
        } else {
            return false;
        }
    }

    public static boolean matchInterface(String address, String interfaceMask) {
        AddressMatcher mask;
        try {
            mask = getAddressMatcher(interfaceMask);
        } catch (Exception var4) {
            return false;
        }

        return mask.match(address);
    }

    public static boolean matchAnyDomain(String name, Collection<String> patterns) {
        if (patterns != null && patterns.size() != 0) {
            Iterator var2 = patterns.iterator();

            String pattern;
            do {
                if (!var2.hasNext()) {
                    return false;
                }

                pattern = (String)var2.next();
            } while(!matchDomain(name, pattern));

            return true;
        } else {
            return false;
        }
    }

    public static boolean matchDomain(String name, String pattern) {
        int index = pattern.indexOf(42);
        if (index == -1) {
            return name.equals(pattern);
        } else {
            String[] names = name.split("\\.");
            String[] patterns = pattern.split("\\.");
            if (patterns.length > names.length) {
                return false;
            } else {
                int nameIndexDiff = names.length - patterns.length;

                for(int i = patterns.length - 1; i > -1; --i) {
                    if (!"*".equals(patterns[i]) && !patterns[i].equals(names[i + nameIndexDiff])) {
                        return false;
                    }
                }

                return true;
            }
        }
    }

    public static AddressHolder getAddressHolder(String address) {
        return getAddressHolder(address, -1);
    }

    public static AddressHolder getAddressHolder(String address, int defaultPort) {
        int indexBracketStart = address.indexOf(91);
        int indexBracketEnd = address.indexOf(93, indexBracketStart);
        int indexColon = address.indexOf(58);
        int lastIndexColon = address.lastIndexOf(58);
        int port = defaultPort;
        String scopeId = null;
        String host;
        if (indexColon > -1 && lastIndexColon > indexColon) {
            if (indexBracketStart == 0 && indexBracketEnd > indexBracketStart) {
                host = address.substring(indexBracketStart + 1, indexBracketEnd);
                if (lastIndexColon == indexBracketEnd + 1) {
                    port = Integer.parseInt(address.substring(lastIndexColon + 1));
                }
            } else {
                host = address;
            }

            int indexPercent = host.indexOf(37);
            if (indexPercent != -1) {
                scopeId = host.substring(indexPercent + 1);
                host = host.substring(0, indexPercent);
            }
        } else if (indexColon > 0 && indexColon == lastIndexColon) {
            host = address.substring(0, indexColon);
            port = Integer.parseInt(address.substring(indexColon + 1));
        } else {
            host = address;
        }

        return new AddressHolder(host, port, scopeId);
    }

    public static boolean isIpAddress(String address) {
        try {
            getAddressMatcher(address);
            return true;
        } catch (InvalidAddressException var2) {
            return false;
        }
    }

    public static InetAddress fixScopeIdAndGetInetAddress(InetAddress inetAddress) throws SocketException {
        if (!(inetAddress instanceof Inet6Address)) {
            return inetAddress;
        } else if (!inetAddress.isLinkLocalAddress() && !inetAddress.isSiteLocalAddress()) {
            return inetAddress;
        } else {
            Inet6Address inet6Address = (Inet6Address)inetAddress;
            if (inet6Address.getScopeId() <= 0 && inet6Address.getScopedInterface() == null) {
                Inet6Address resultInetAddress = findRealInet6Address(inet6Address);
                return (InetAddress)(resultInetAddress == null ? inetAddress : resultInetAddress);
            } else {
                return inetAddress;
            }
        }
    }

    private static Inet6Address findRealInet6Address(Inet6Address inet6Address) throws SocketException {
        Inet6Address resultInetAddress = null;
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

        while(interfaces.hasMoreElements()) {
            NetworkInterface ni = (NetworkInterface)interfaces.nextElement();
            Enumeration<InetAddress> addresses = ni.getInetAddresses();

            while(addresses.hasMoreElements()) {
                InetAddress address = (InetAddress)addresses.nextElement();
                if (isInet6Compatible(address, inet6Address)) {
                    if (resultInetAddress != null) {
                        throw new IllegalArgumentException("This address " + inet6Address + " is bound to more than one network interface!");
                    }

                    resultInetAddress = (Inet6Address)address;
                }
            }
        }

        return resultInetAddress;
    }

    private static boolean isInet6Compatible(InetAddress address, Inet6Address inet6Address) {
        if (!(address instanceof Inet6Address)) {
            return false;
        } else {
            return Arrays.equals(address.getAddress(), inet6Address.getAddress());
        }
    }

    public static Inet6Address getInetAddressFor(Inet6Address inetAddress, String scope) throws UnknownHostException, SocketException {
        if (!inetAddress.isLinkLocalAddress() && !inetAddress.isSiteLocalAddress()) {
            return inetAddress;
        } else {
            char[] chars = scope.toCharArray();
            boolean numeric = true;
            char[] var4 = chars;
            int var5 = chars.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                char c = var4[var6];
                if (!Character.isDigit(c)) {
                    numeric = false;
                    break;
                }
            }

            return numeric ? Inet6Address.getByAddress((String)null, inetAddress.getAddress(), Integer.parseInt(scope)) : Inet6Address.getByAddress((String)null, inetAddress.getAddress(), NetworkInterface.getByName(scope));
        }
    }

    public static Collection<Inet6Address> getPossibleInetAddressesFor(Inet6Address inet6Address) {
        if ((inet6Address.isSiteLocalAddress() || inet6Address.isLinkLocalAddress()) && inet6Address.getScopeId() <= 0 && inet6Address.getScopedInterface() == null) {
            LinkedList<Inet6Address> possibleAddresses = new LinkedList();

            try {
                Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

                while(interfaces.hasMoreElements()) {
                    NetworkInterface ni = (NetworkInterface)interfaces.nextElement();
                    addPossibleAddress(inet6Address, possibleAddresses, ni);
                }
            } catch (IOException var4) {
                EmptyStatement.ignore(var4);
            }

            if (possibleAddresses.isEmpty()) {
                throw new IllegalArgumentException("Could not find a proper network interface to connect to " + inet6Address);
            } else {
                return possibleAddresses;
            }
        } else {
            return Collections.singleton(inet6Address);
        }
    }

    private static void addPossibleAddress(Inet6Address inet6Address, Deque<Inet6Address> possibleAddresses, NetworkInterface ni) throws UnknownHostException {
        Enumeration<InetAddress> addresses = ni.getInetAddresses();

        while(true) {
            InetAddress address;
            do {
                do {
                    if (!addresses.hasMoreElements()) {
                        return;
                    }

                    address = (InetAddress)addresses.nextElement();
                } while(address instanceof Inet4Address);
            } while((!inet6Address.isLinkLocalAddress() || !address.isLinkLocalAddress()) && (!inet6Address.isSiteLocalAddress() || !address.isSiteLocalAddress()));

            Inet6Address newAddress = Inet6Address.getByAddress((String)null, inet6Address.getAddress(), ((Inet6Address)address).getScopeId());
            possibleAddresses.addFirst(newAddress);
        }
    }

    public static Collection<String> getMatchingIpv4Addresses(AddressMatcher addressMatcher) {
        if (addressMatcher.isIPv6()) {
            throw new IllegalArgumentException("Cannot wildcard matching for IPv6: " + addressMatcher);
        } else {
            Collection<String> addresses = new HashSet();
            String first3 = addressMatcher.address[0] + '.' + addressMatcher.address[1] + '.' + addressMatcher.address[2];
            String lastPart = addressMatcher.address[3];
            int start;
            if ("*".equals(lastPart)) {
                for(start = 0; start <= 255; ++start) {
                    addresses.add(first3 + '.' + start);
                }
            } else if (lastPart.indexOf(45) > 0) {
                int dashPos = lastPart.indexOf(45);
                start = Integer.parseInt(lastPart.substring(0, dashPos));
                int end = Integer.parseInt(lastPart.substring(dashPos + 1));

                for(int j = start; j <= end; ++j) {
                    addresses.add(first3 + '.' + j);
                }
            } else {
                addresses.add(addressMatcher.getAddress());
            }

            return addresses;
        }
    }

    public static AddressMatcher getAddressMatcher(String address) {
        int indexColon = address.indexOf(58);
        int lastIndexColon = address.lastIndexOf(58);
        int indexDot = address.indexOf(46);
        int lastIndexDot = address.lastIndexOf(46);
        Object matcher;
        if (indexColon > -1 && lastIndexColon > indexColon) {
            if (indexDot == -1) {
                matcher = new Ip6AddressMatcher();
                parseIpv6((AddressMatcher)matcher, address);
            } else {
                if (indexDot >= lastIndexDot) {
                    throw new InvalidAddressException(address);
                }

                int lastIndexColon2 = address.lastIndexOf(58);
                String host2 = address.substring(lastIndexColon2 + 1);
                matcher = new Ip4AddressMatcher();
                parseIpv4((AddressMatcher)matcher, host2);
            }
        } else {
            if (indexDot <= -1 || lastIndexDot <= indexDot || indexColon != -1) {
                throw new InvalidAddressException(address);
            }

            matcher = new Ip4AddressMatcher();
            parseIpv4((AddressMatcher)matcher, address);
        }

        return (AddressMatcher)matcher;
    }

    private static void parseIpv4(AddressMatcher matcher, String address) {
        String[] parts = address.split("\\.");
        if (parts.length != 4) {
            throw new InvalidAddressException(address);
        } else {
            String[] var3 = parts;
            int var4 = parts.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                String part = var3[var5];
                if (!isValidIpAddressPart(part, false)) {
                    throw new InvalidAddressException(address);
                }
            }

            matcher.setAddress(parts);
        }
    }

    private static boolean isValidIpAddressPart(String part, boolean ipv6) {
        boolean isValid = true;
        if (part.length() == 1 && "*".equals(part)) {
            return true;
        } else {
            int rangeIndex = part.indexOf(45);
            if (rangeIndex <= -1 || rangeIndex == part.lastIndexOf(45) && rangeIndex != part.length() - 1) {
                String[] subParts;
                if (rangeIndex > -1) {
                    subParts = part.split("\\-");
                } else {
                    subParts = new String[]{part};
                }

                try {
                    String[] var5 = subParts;
                    int var6 = subParts.length;

                    for(int var7 = 0; var7 < var6; ++var7) {
                        String subPart = var5[var7];
                        int num;
                        if (ipv6) {
                            num = Integer.parseInt(subPart, 16);
                            if (num > 65535) {
                                isValid = false;
                                break;
                            }
                        } else {
                            num = Integer.parseInt(subPart);
                            if (num > 255) {
                                isValid = false;
                                break;
                            }
                        }
                    }
                } catch (NumberFormatException var10) {
                    isValid = false;
                }

                return isValid;
            } else {
                return false;
            }
        }
    }

    private static void parseIpv6(AddressMatcher matcher, String addrs) {
        String address = addrs;
        String[] parts;
        if (addrs.indexOf(37) > -1) {
            parts = addrs.split("\\%");
            address = parts[0];
        }

        parts = address.split("((?<=:)|(?=:))");
        Collection<String> ipString = parseIPV6parts(parts, address);
        if (ipString.size() != 8) {
            throw new InvalidAddressException(address);
        } else {
            String[] addressParts = (String[])ipString.toArray(new String[ipString.size()]);
            checkIfAddressPartsAreValid(addressParts, address);
            matcher.setAddress(addressParts);
        }
    }

    private static Collection<String> parseIPV6parts(String[] parts, String address) {
        LinkedList<String> ipString = new LinkedList();
        int count = 0;
        int mark = -1;

        int remaining;
        for(remaining = 0; remaining < parts.length; ++remaining) {
            String part = parts[remaining];
            String nextPart = remaining < parts.length - 1 ? parts[remaining + 1] : null;
            if (!"".equals(part)) {
                if (":".equals(part) && ":".equals(nextPart)) {
                    if (mark != -1) {
                        throw new InvalidAddressException(address);
                    }

                    mark = count;
                } else if (!":".equals(part)) {
                    ++count;
                    ipString.add(part);
                }
            }
        }

        if (mark > -1) {
            remaining = 8 - count;

            for(int i = 0; i < remaining; ++i) {
                ipString.add(i + mark, "0");
            }
        }

        return ipString;
    }

    private static void checkIfAddressPartsAreValid(String[] addressParts, String address) {
        String[] var2 = addressParts;
        int var3 = addressParts.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            String part = var2[var4];
            if (!isValidIpAddressPart(part, true)) {
                throw new InvalidAddressException(address);
            }
        }

    }
    class AddressUtil$Ip6AddressMatcher extends AddressUtil.AddressMatcher {
        public AddressUtil$Ip6AddressMatcher() {
            super(new String[8]);
        }

        public boolean isIPv4() {
            return false;
        }

        public boolean isIPv6() {
            return true;
        }

        public void setAddress(String[] ip) {
            System.arraycopy(ip, 0, this.address, 0, ip.length);
        }

        public boolean match(AddressUtil.AddressMatcher matcher) {
            if (matcher.isIPv4()) {
                return false;
            } else {
                AddressUtil$Ip6AddressMatcher a = (AddressUtil$Ip6AddressMatcher)matcher;
                String[] mask = this.address;
                String[] input = a.address;
                return this.match(mask, input, 16);
            }
        }

        public String getAddress() {
            StringBuilder sb = new StringBuilder();

            for(int i = 0; i < this.address.length; ++i) {
                sb.append(this.address[i]);
                if (i != this.address.length - 1) {
                    sb.append(':');
                }
            }

            return sb.toString();
        }

        @Override
        public boolean match(com.hazelcast.internal.util.AddressUtil.AddressMatcher var1) {
            return false;
        }
    }

    public static class InvalidAddressException extends IllegalArgumentException {
        public InvalidAddressException(String message) {
            this(message, true);
        }

        public InvalidAddressException(String message, boolean prependText) {
            super((prependText ? "Illegal IP address format: " : "") + message);
        }
    }

    static class Ip6AddressMatcher extends com.hazelcast.internal.util.AddressUtil.AddressMatcher {
        Ip6AddressMatcher() {
            super(new String[8]);
        }

        public boolean isIPv4() {
            return false;
        }

        public boolean isIPv6() {
            return true;
        }

        public void setAddress(String[] ip) {
            System.arraycopy(ip, 0, this.address, 0, ip.length);
        }

        public boolean match(com.hazelcast.internal.util.AddressUtil.AddressMatcher matcher) {
            if (matcher.isIPv4()) {
                return false;
            } else {
                AddressUtil.Ip6AddressMatcher a = (AddressUtil.Ip6AddressMatcher)matcher;
                String[] mask = this.address;
                String[] input = a.address;
                return this.match(mask, input, 16);
            }
        }

        public String getAddress() {
            StringBuilder sb = new StringBuilder();

            for(int i = 0; i < this.address.length; ++i) {
                sb.append(this.address[i]);
                if (i != this.address.length - 1) {
                    sb.append(':');
                }
            }

            return sb.toString();
        }
    }

    static class Ip4AddressMatcher extends com.hazelcast.internal.util.AddressUtil.AddressMatcher {
        Ip4AddressMatcher() {
            super(new String[4]);
        }

        public boolean isIPv4() {
            return true;
        }

        public boolean isIPv6() {
            return false;
        }

        public void setAddress(String[] ip) {
            System.arraycopy(ip, 0, this.address, 0, ip.length);
        }

        public boolean match(com.hazelcast.internal.util.AddressUtil.AddressMatcher matcher) {
            if (matcher.isIPv6()) {
                return false;
            } else {
                String[] mask = this.address;
                String[] input = ((Ip4AddressMatcher)matcher).address;
                return this.match(mask, input, 10);
            }
        }

        public String getAddress() {
            StringBuilder sb = new StringBuilder();

            for(int i = 0; i < this.address.length; ++i) {
                sb.append(this.address[i]);
                if (i != this.address.length - 1) {
                    sb.append('.');
                }
            }

            return sb.toString();
        }
    }

    public abstract static class AddressMatcher {
        protected final String[] address;

        protected AddressMatcher(String[] address) {
            this.address = address;
        }

        public abstract boolean isIPv4();

        public abstract boolean isIPv6();

        public abstract void setAddress(String[] var1);

        protected final boolean match(String[] mask, String[] input, int radix) {
            if (input != null && mask != null) {
                for(int i = 0; i < mask.length; ++i) {
                    if (!this.doMatch(mask[i], input[i], radix)) {
                        return false;
                    }
                }

                return true;
            } else {
                return false;
            }
        }

        protected final boolean doMatch(String mask, String input, int radix) {
            int dashIndex = mask.indexOf(45);
            int ipa = Integer.parseInt(input, radix);
            if ("*".equals(mask)) {
                return true;
            } else {
                int start;
                if (dashIndex != -1) {
                    start = Integer.parseInt(mask.substring(0, dashIndex).trim(), radix);
                    int end = Integer.parseInt(mask.substring(dashIndex + 1).trim(), radix);
                    if (ipa >= start && ipa <= end) {
                        return true;
                    }
                } else {
                    start = Integer.parseInt(mask, radix);
                    if (start == ipa) {
                        return true;
                    }
                }

                return false;
            }
        }

        public abstract String getAddress();

        public abstract boolean match(com.hazelcast.internal.util.AddressUtil.AddressMatcher var1);

        public boolean match(String address) {
            try {
                return this.match(com.hazelcast.internal.util.AddressUtil.getAddressMatcher(address));
            } catch (Exception var3) {
                return false;
            }
        }

        public String toString() {
            return this.getClass().getSimpleName() + '{' + this.getAddress() + '}';
        }
    }

    public static class AddressHolder {
        private final String address;
        private final String scopeId;
        private final int port;

        public AddressHolder(String address, int port, String scopeId) {
            this.address = address;
            this.scopeId = scopeId;
            this.port = port;
        }

        public String toString() {
            return "AddressHolder [" + this.address + "]:" + this.port;
        }

        public String getAddress() {
            return this.address;
        }

        public String getScopeId() {
            return this.scopeId;
        }

        public int getPort() {
            return this.port;
        }
    }
}
