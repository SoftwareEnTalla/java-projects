//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.action;

import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONObject;

public class LocateActionEvaluator extends BaseEvaluator {
    public LocateActionEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        String filter = this.getArg("filter");
        if (filter instanceof String) {
            return !filter.equalsIgnoreCase("path");
        } else {
            return false;
        }
    }
}
