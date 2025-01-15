//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class AlwaysFalseEvaluator extends BaseEvaluator {
    public AlwaysFalseEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        return false;
    }
}
