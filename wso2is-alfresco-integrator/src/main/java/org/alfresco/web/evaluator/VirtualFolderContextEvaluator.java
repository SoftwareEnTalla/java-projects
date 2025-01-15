//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class VirtualFolderContextEvaluator extends VirtualBaseEvaluator {
    public VirtualFolderContextEvaluator() {
    }

    public boolean evaluate(JSONObject jsonObject) {
        boolean virtualContext = this.isContainer(jsonObject) && this.hasAspect(jsonObject, "smf:smartFolderChild");
        return virtualContext;
    }
}
