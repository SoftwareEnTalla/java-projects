//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class FieldVisibilityInstruction {
    private final Visibility showOrHide;
    private final String fieldId;
    private final List<Mode> forModes;

    public FieldVisibilityInstruction(String showOrHide, String fieldId, String modesString) {
        this.showOrHide = Visibility.visibilityFromString(showOrHide);
        this.fieldId = fieldId;
        if (modesString != null && modesString.length() != 0) {
            this.forModes = Mode.modesFromString(modesString);
        } else {
            this.forModes = Arrays.asList(Mode.values());
        }

    }

    public Visibility getShowOrHide() {
        return this.showOrHide;
    }

    public String getFieldId() {
        return this.fieldId;
    }

    public List<Mode> getModes() {
        return Collections.unmodifiableList(this.forModes);
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(this.showOrHide).append(" ").append(this.fieldId).append(" ").append(this.forModes);
        return result.toString();
    }
}
