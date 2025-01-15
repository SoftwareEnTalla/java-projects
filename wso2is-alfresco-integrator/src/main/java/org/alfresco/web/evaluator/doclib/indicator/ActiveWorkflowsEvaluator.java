//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.indicator;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONObject;

public class ActiveWorkflowsEvaluator extends BaseEvaluator {
    private final String VALUE_ACTIVEWORKFLOWS = "activeWorkflows";

    public ActiveWorkflowsEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        try {
            Number workflows = (Number)jsonObject.get("activeWorkflows");
            return workflows != null && workflows.intValue() > 0;
        } catch (Exception var3) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + var3.getMessage());
        }
    }
}
