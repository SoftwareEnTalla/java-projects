//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.indicator;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class LockedEvaluator extends BaseEvaluator {
    private static final String ASPECT_TRANSFERRED = "trx:transferred";
    private static final String ASPECT_WORKINGCOPY = "cm:workingcopy";
    private static final String PROP_LOCKOWNER = "cm:lockOwner";
    private static final String PROP_WORKINGCOPYOWNER = "cm:workingCopyOwner";

    public LockedEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        try {
            JSONArray nodeAspects = this.getNodeAspects(jsonObject);
            if (nodeAspects == null) {
                return false;
            } else if (nodeAspects.contains("cm:workingcopy")) {
                return !this.getMatchesCurrentUser(jsonObject, "cm:workingCopyOwner");
            } else if (nodeAspects.contains("trx:transferred")) {
                return false;
            } else {
                return this.getIsLocked(jsonObject) && !this.getMatchesCurrentUser(jsonObject, "cm:lockOwner");
            }
        } catch (Exception var3) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + var3.getMessage());
        }
    }
}
