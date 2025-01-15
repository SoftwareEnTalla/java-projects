//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class HasContentEvaluator extends BaseEvaluator {
    public HasContentEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        return this.getHasContent(jsonObject);
    }
}
