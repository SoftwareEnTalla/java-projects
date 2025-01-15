//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class CMMServicePut extends CMMService {
    private static final Log logger = LogFactory.getLog(CMMServicePut.class);

    public CMMServicePut() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> result = new HashMap();
        result.put("result", "{\"success\":true}");

        try {
            JSONObject json = this.getJsonBody(req);
            if (json == null) {
                throw new IllegalArgumentException("No JSON body was provided.");
            }

            String modelName = (String)json.get("modelName");
            if (modelName == null || modelName.length() == 0) {
                throw new IllegalArgumentException("No 'modelName' was provided");
            }

            if (json.get("operation") != null) {
                result.put("result", this.serviceModelOperation(status, modelName, json));
            }
        } catch (IOException var7) {
            this.errorResponse(status, var7.getMessage());
        }

        return result;
    }
}
