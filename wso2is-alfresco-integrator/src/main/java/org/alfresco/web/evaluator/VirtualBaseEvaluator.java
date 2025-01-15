//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public abstract class VirtualBaseEvaluator extends BaseEvaluator {
    public VirtualBaseEvaluator() {
    }

    Boolean isContainer(JSONObject jsonObject) {
        return (Boolean)this.getJSONValue(jsonObject, "node.isContainer");
    }

    boolean notInVirtualContext(JSONObject jsonObject) {
        boolean virtual = this.hasAspect(jsonObject, "smf:smartFolder") || this.hasAspect(jsonObject, "smf:smartFolderChild");
        boolean isContainer = this.isContainer(jsonObject);
        boolean virtualContext = isContainer && this.hasAspect(jsonObject, "smf:smartFolderChild");
        return !virtual && !virtualContext;
    }

    boolean hasAspect(JSONObject jsonObject, String aspect) {
        JSONArray nodeAspects = this.getNodeAspects(jsonObject);
        return nodeAspects.contains(aspect);
    }
}
