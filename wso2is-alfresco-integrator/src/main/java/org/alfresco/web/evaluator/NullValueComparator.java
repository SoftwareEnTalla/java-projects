//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

public class NullValueComparator implements Comparator {
    private String value = null;

    public NullValueComparator() {
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean compare(Object nodeValue) {
        boolean match = this.value.equalsIgnoreCase("true");
        return match == (nodeValue == null);
    }
}
