//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DocsEdition implements Serializable {
    private static final long serialVersionUID = -6180536415511757664L;
    public static final String COMMUNITY = "community";
    public static final String CLOUD = "cloud";
    private final String value;

    public DocsEdition() {
        this(null, null, false);
    }

    public DocsEdition(boolean isInCloud) {
        this(null, null, isInCloud);
    }

    public DocsEdition(String edition, String specificationVersion, boolean isInCloud) {
        String value = "community";
        if (isInCloud) {
            value = "cloud";
        } else if ("ENTERPRISE".equals(edition) && specificationVersion != null) {
            Matcher matcher = Pattern.compile("^(\\d+\\.\\d+)").matcher(specificationVersion);
            if (matcher.find()) {
                value = matcher.group();
            }
        }

        this.value = value;
    }

    public String getValue() {
        return this.value;
    }
}
