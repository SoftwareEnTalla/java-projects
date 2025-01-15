//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import java.util.Iterator;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class HasAnyAspectEvaluator extends BaseEvaluator {
    private ArrayList<String> aspects;

    public HasAnyAspectEvaluator() {
    }

    public void setAspects(ArrayList<String> aspects) {
        this.aspects = aspects;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.aspects.size() == 0) {
            return false;
        } else {
            try {
                JSONArray nodeAspects = this.getNodeAspects(jsonObject);
                if (nodeAspects == null) {
                    return false;
                } else {
                    Iterator var3 = this.aspects.iterator();

                    String aspect;
                    do {
                        if (!var3.hasNext()) {
                            return false;
                        }

                        aspect = (String)var3.next();
                    } while(!nodeAspects.contains(aspect));

                    return true;
                }
            } catch (Exception var5) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var5.getMessage());
            }
        }
    }
}
