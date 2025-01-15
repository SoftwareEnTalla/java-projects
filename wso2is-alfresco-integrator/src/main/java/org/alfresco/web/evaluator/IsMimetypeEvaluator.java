//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONObject;

public class IsMimetypeEvaluator extends BaseEvaluator {
    private ArrayList<String> mimetypes;

    public IsMimetypeEvaluator() {
    }

    public void setMimetypes(ArrayList<String> mimetypes) {
        this.mimetypes = mimetypes;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.mimetypes.size() == 0) {
            return false;
        } else {
            try {
                JSONObject node = (JSONObject)jsonObject.get("node");
                if (node == null) {
                    return false;
                } else {
                    String mimetype = (String)node.get("mimetype");
                    return mimetype != null && this.mimetypes.contains(mimetype);
                }
            } catch (Exception var4) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var4.getMessage());
            }
        }
    }
}
