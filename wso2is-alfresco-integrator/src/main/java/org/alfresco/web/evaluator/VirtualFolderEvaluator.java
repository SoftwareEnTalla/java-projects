//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class VirtualFolderEvaluator extends VirtualBaseEvaluator {
    public VirtualFolderEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        return this.hasAspect(jsonObject, "smf:smartFolder");
    }
}
