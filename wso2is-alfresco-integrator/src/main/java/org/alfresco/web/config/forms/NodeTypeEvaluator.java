//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

public class NodeTypeEvaluator extends NodeMetadataBasedEvaluator {
    protected static final String JSON_TYPE = "type";
    private static Log logger = LogFactory.getLog(NodeTypeEvaluator.class);

    public NodeTypeEvaluator() {
    }

    protected Log getLogger() {
        return logger;
    }

    protected boolean checkJsonAgainstCondition(String condition, String jsonResponseString) {
        boolean result = false;

        try {
            JSONObject json = new JSONObject(new JSONTokener(jsonResponseString));
            Object typeObj = null;
            if (json.has("type")) {
                typeObj = json.get("type");
            }

            if (typeObj instanceof String typeString) {
                result = condition.equals(typeString);
            }
        } catch (JSONException var7) {
            if (this.getLogger().isWarnEnabled()) {
                this.getLogger().warn("Failed to find node type in JSON response from metadata service: " + var7.getMessage());
            }
        }

        return result;
    }
}
