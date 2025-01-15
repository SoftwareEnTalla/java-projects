//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

public class AspectEvaluator extends NodeMetadataBasedEvaluator {
    protected static final String JSON_ASPECTS = "aspects";
    private static Log logger = LogFactory.getLog(AspectEvaluator.class);

    public AspectEvaluator() {
    }

    protected Log getLogger() {
        return logger;
    }

    protected boolean checkJsonAgainstCondition(String condition, String jsonResponseString) {
        boolean result = false;

        try {
            JSONObject json = new JSONObject(new JSONTokener(jsonResponseString));
            Object aspectsObj = json.get("aspects");
            if (aspectsObj instanceof JSONArray aspectsArray) {
                for(int i = 0; i < aspectsArray.length(); ++i) {
                    String nextAspect = aspectsArray.getString(i);
                    if (condition.equals(nextAspect)) {
                        result = true;
                        break;
                    }
                }
            }
        } catch (JSONException var9) {
            if (this.getLogger().isWarnEnabled()) {
                this.getLogger().warn("Failed to find aspects in JSON response from metadata service.", var9);
            }
        }

        return result;
    }
}
