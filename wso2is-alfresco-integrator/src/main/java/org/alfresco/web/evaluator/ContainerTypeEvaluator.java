//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONObject;

public class ContainerTypeEvaluator extends BaseEvaluator {
    private ArrayList<String> types;

    public ContainerTypeEvaluator() {
    }

    public void setTypes(ArrayList<String> types) {
        this.types = types;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.types.size() == 0) {
            return false;
        } else {
            try {
                return this.types.contains(this.getContainerType(jsonObject));
            } catch (Exception var3) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var3.getMessage());
            }
        }
    }
}
