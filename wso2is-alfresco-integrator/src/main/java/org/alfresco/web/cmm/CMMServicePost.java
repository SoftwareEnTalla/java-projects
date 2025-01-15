//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.web.cmm.CMMService.FormOperationEnum;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.json.simple.JSONObject;
import org.springframework.extensions.surf.util.XMLUtil;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class CMMServicePost extends CMMService {
    private static final Log logger = LogFactory.getLog(CMMServicePost.class);

    public CMMServicePost() {
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
            } else {
                String entityId = (String)json.get("entity");
                String formExtension;
                if (entityId != null && entityId.length() != 0) {
                    formExtension = (String)json.get("form");
                    String formOp = (String)json.get("formOperation");
                    CMMService.FormOperationEnum op = FormOperationEnum.Update;
                    if (formOp != null && formOp.length() != 0) {
                        op = FormOperationEnum.valueOf(formOp);
                    }

                    this.buildExtensionModule(status, modelName, new CMMService.FormOperation(op, entityId, formExtension));
                } else {
                    formExtension = (String)json.get("forms");
                    if (formExtension != null && formExtension.length() != 0) {
                        Map<String, String> forms = new HashMap();
                        Document doc = XMLUtil.parse(formExtension);
                        List<Element> formDefNodes = new ArrayList();
                        Iterator var12 = doc.selectNodes("/module/configurations/config[@condition='FormDefinition']/form-definition").iterator();

                        while(var12.hasNext()) {
                            Object obj = var12.next();
                            formDefNodes.add((Element)obj);
                        }

                        if (formDefNodes != null) {
                            var12 = formDefNodes.iterator();

                            while(var12.hasNext()) {
                                Element node = (Element)var12.next();
                                forms.put(node.attributeValue("id"), node.getText());
                            }
                        }

                        this.buildExtensionModule(status, modelName, new CMMService.FormOperation(FormOperationEnum.Create, forms), false);
                    }
                }
            }
        } catch (DocumentException | IOException var14) {
            this.errorResponse(status, var14.getMessage());
        }

        return result;
    }
}
