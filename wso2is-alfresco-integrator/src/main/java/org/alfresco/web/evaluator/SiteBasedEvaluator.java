//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class SiteBasedEvaluator extends BaseEvaluator {
    public SiteBasedEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        return this.getSiteId(jsonObject) != null;
    }
}
