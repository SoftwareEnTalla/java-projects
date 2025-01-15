//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.action;

import java.util.Map;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.evaluator.BaseEvaluator;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

public class IsNodeEditableAos extends BaseEvaluator {
    private static final String PROP_NAME = "cm:name";
    private Map<String, String> mimetypeExtensionMap;

    public IsNodeEditableAos() {
    }

    public void setMimetypeExtensionMap(Map<String, String> mimetypeExtensionMap) {
        this.mimetypeExtensionMap = mimetypeExtensionMap;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.mimetypeExtensionMap.size() == 0) {
            return false;
        } else {
            try {
                String mimetype = this.getNodeMimetype(jsonObject);
                String name = (String)this.getProperty(jsonObject, "cm:name");
                if (!StringUtils.isEmpty(mimetype) && !StringUtils.isEmpty(name)) {
                    String fileExtension = FilenameUtils.getExtension(name);
                    if (StringUtils.isEmpty(fileExtension)) {
                        return false;
                    } else {
                        String expectedExtension = (String)this.mimetypeExtensionMap.get(mimetype);
                        return expectedExtension != null && expectedExtension.equals(fileExtension.toLowerCase());
                    }
                } else {
                    return false;
                }
            } catch (Exception var6) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var6.getMessage());
            }
        }
    }
}
