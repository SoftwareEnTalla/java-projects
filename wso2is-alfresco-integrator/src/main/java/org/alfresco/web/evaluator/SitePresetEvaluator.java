//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONObject;

public class SitePresetEvaluator extends BaseEvaluator {
    private ArrayList<String> presets;

    public SitePresetEvaluator() {
    }

    public void setPresets(ArrayList<String> presets) {
        this.presets = presets;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.presets.size() == 0) {
            return false;
        } else {
            try {
                return this.presets.contains(this.getSitePreset(jsonObject));
            } catch (Exception var3) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var3.getMessage());
            }
        }
    }
}
