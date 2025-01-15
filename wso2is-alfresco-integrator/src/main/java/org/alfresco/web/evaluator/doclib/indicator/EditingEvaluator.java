//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.indicator;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class EditingEvaluator extends BaseEvaluator {
    private static final String ASPECT_WORKINGCOPY = "cm:workingcopy";
    private static final String PROP_WORKINGCOPYOWNER = "cm:workingCopyOwner";

    public EditingEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        try {
            JSONArray nodeAspects = this.getNodeAspects(jsonObject);
            if (nodeAspects == null) {
                return false;
            } else {
                return nodeAspects.contains("cm:workingcopy") ? this.getMatchesCurrentUser(jsonObject, "cm:workingCopyOwner") : false;
            }
        } catch (Exception var3) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + var3.getMessage());
        }
    }
}
