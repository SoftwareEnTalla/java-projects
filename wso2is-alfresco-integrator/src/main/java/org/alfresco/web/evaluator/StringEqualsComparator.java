//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

public class StringEqualsComparator implements Comparator {
    private Boolean caseInsensitive = true;
    private String value = null;

    public StringEqualsComparator() {
    }

    public void setCaseInsensitive(Boolean caseInsensitive) {
        this.caseInsensitive = caseInsensitive;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean compare(Object nodeValue) {
        if (nodeValue == null) {
            return false;
        } else {
            return this.caseInsensitive ? nodeValue.toString().equalsIgnoreCase(this.value) : nodeValue.toString().equals(this.value);
        }
    }
}
