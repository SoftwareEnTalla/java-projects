//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

public class ControlParam {
    private final String name;
    private String value;

    public ControlParam(String name, String value) {
        if (value == null) {
            value = "";
        }

        this.name = name;
        this.value = value;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    void setValue(String newValue) {
        this.value = newValue;
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(this.name).append(":").append(this.value);
        return result.toString();
    }

    public int hashCode() {
        return this.name.hashCode() + 7 * this.value.hashCode();
    }

    public boolean equals(Object otherObj) {
        if (otherObj == this) {
            return true;
        } else if (otherObj != null && otherObj.getClass().equals(this.getClass())) {
            ControlParam otherCP = (ControlParam)otherObj;
            return otherCP.name.equals(this.name) && otherCP.value.equals(this.value);
        } else {
            return false;
        }
    }
}
