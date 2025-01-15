//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.action;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONObject;

public class EditableByCurrentUser extends BaseEvaluator {
    private static final String PROP_WORKINGCOPYOWNER = "cm:workingCopyOwner";
    private static final String PROP_LOCKOWNER = "cm:lockOwner";
    private static final String PROP_LOCKTYPE = "cm:lockType";
    private static final String NODE_LOCK = "NODE_LOCK";

    public EditableByCurrentUser() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        try {
            Object lockType = this.getProperty(jsonObject, "cm:lockType");
            if (lockType != null && ((String)lockType).equalsIgnoreCase("NODE_LOCK")) {
                return false;
            } else if (this.getIsLocked(jsonObject)) {
                return this.getMatchesCurrentUser(jsonObject, "cm:lockOwner");
            } else {
                return this.getIsWorkingCopy(jsonObject) ? this.getMatchesCurrentUser(jsonObject, "cm:workingCopyOwner") : true;
            }
        } catch (Exception var3) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + var3.getMessage());
        }
    }
}
