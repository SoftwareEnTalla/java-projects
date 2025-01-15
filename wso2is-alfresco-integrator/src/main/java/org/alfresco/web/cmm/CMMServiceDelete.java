//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.alfresco.web.cmm.CMMService.FormOperationEnum;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class CMMServiceDelete extends CMMService {
    private static final Log logger = LogFactory.getLog(CMMServiceDelete.class);

    public CMMServiceDelete() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> result = new HashMap();
        result.put("result", "{\"success\":true}");

        try {
            JSONObject json = this.getJsonBody(req);
            if (json != null) {
                String modelName = (String)json.get("modelName");
                if (modelName == null || modelName.length() == 0) {
                    throw new IllegalArgumentException("No 'modelName' was provided");
                }

                if (json.get("operation") != null) {
                    result.put("result", this.serviceModelOperation(status, modelName, json));
                }
            } else {
                Map<String, String> params = req.getServiceMatch().getTemplateVars();
                String modelName = (String)params.get("model");
                String entityId = (String)params.get("entity");
                if (modelName != null && modelName.length() != 0 && entityId != null && entityId.length() != 0) {
                    String form = (String)params.get("form");
                    if (form != null && form.length() != 0) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Updating extension for model: " + modelName + " due to deleted form definition for entity: " + entityId);
                        }

                        this.buildExtensionModule(status, modelName, new CMMService.FormOperation(FormOperationEnum.Delete, entityId, form));
                    } else if (logger.isDebugEnabled()) {
                        logger.debug("Updating extension for model: " + modelName + " due to deleted entity: " + entityId);
                    }
                }
            }
        } catch (IOException var10) {
            this.errorResponse(status, var10.getMessage());
        }

        return result;
    }
}
