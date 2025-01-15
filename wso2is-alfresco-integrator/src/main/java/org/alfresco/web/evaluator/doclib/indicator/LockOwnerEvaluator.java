//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.indicator;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class LockOwnerEvaluator extends BaseEvaluator {
    private static final String ASPECT_TRANSFERRED = "trx:transferred";
    private static final String ASPECT_WORKINGCOPY = "cm:workingcopy";
    private static final String PROP_LOCKOWNER = "cm:lockOwner";

    public LockOwnerEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        try {
            if (this.getIsLocked(jsonObject)) {
                JSONArray nodeAspects = this.getNodeAspects(jsonObject);
                if (nodeAspects == null) {
                    return false;
                }

                if (!nodeAspects.contains("trx:transferred") && !nodeAspects.contains("cm:workingcopy")) {
                    return this.getMatchesCurrentUser(jsonObject, "cm:lockOwner");
                }
            }

            return false;
        } catch (Exception var3) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + var3.getMessage());
        }
    }
}
