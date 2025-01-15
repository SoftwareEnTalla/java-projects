//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class CMMServiceGet extends CMMService {
    private static final Log logger = LogFactory.getLog(CMMServiceGet.class);

    public CMMServiceGet() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> result = new HashMap();
        String modelId = (String)req.getServiceMatch().getTemplateVars().get("model");
        if (modelId != null && modelId.length() != 0) {
            String entityId = (String)req.getServiceMatch().getTemplateVars().get("entity");
            if (entityId != null && entityId.length() != 0) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Retrieving form definition for model: " + modelId + " and entity: " + entityId);
                }

                String formDef = (String)this.getFormDefinitions(modelId).get(entityId);
                if (logger.isDebugEnabled()) {
                    logger.debug("Form definition: " + (formDef != null ? formDef : "null"));
                }

                result.put("form", formDef != null ? formDef : "");
            } else if (req.getServiceMatch().getTemplate().endsWith("/forms")) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Retrieving form states for model: " + modelId);
                }

                Map<String, String> defs = this.getFormDefinitions(modelId);
                result.put("forms", new ArrayList(defs.keySet()));
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Retrieving module ID for model: " + modelId);
                }

                result.put("moduleId", this.getExtensionModule(modelId) != null ? this.buildModuleId(modelId) : "");
            }

            return result;
        } else {
            throw new IllegalArgumentException("model name is mandatory");
        }
    }
}
