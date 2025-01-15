//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts.forms;

import java.util.Comparator;

public class OptionsComparator implements Comparator<String> {
    public static final String delimiter = "|";

    public OptionsComparator() {
    }

    public int compare(String o1, String o2) {
        return this.getLabel(o1).compareTo(this.getLabel(o2));
    }

    protected String getLabel(String s) {
        String label = null;
        int delimiterIndex = s.indexOf("|");
        if (delimiterIndex != -1) {
            label = s.substring(delimiterIndex);
        } else {
            label = s;
        }

        return label.toLowerCase();
    }
}
