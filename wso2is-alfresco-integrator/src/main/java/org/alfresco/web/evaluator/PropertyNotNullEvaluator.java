//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class PropertyNotNullEvaluator extends BaseEvaluator {
    private String property = null;

    public PropertyNotNullEvaluator() {
    }

    public void setProperty(String name) {
        this.property = name;
    }

    public boolean evaluate(JSONObject jsonObject) {
        boolean result = false;
        if (this.property != null) {
            Object value = this.getProperty(jsonObject, this.property);
            result = value != null;
        }

        return result;
    }
}
