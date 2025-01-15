//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.resolver.doclib;

import org.json.simple.JSONObject;

public class DefaultDoclistActionGroupResolver implements DoclistActionGroupResolver {
    public DefaultDoclistActionGroupResolver() {
    }

    public String resolve(JSONObject jsonObject, String view) {
        JSONObject node = (JSONObject)jsonObject.get("node");
        boolean isContainer = (Boolean)node.get("isContainer");
        String actionGroupId;
        if (isContainer) {
            actionGroupId = "folder-";
        } else {
            actionGroupId = "document-";
        }

        boolean isLink = (Boolean)node.get("isLink");
        if (isLink) {
            actionGroupId = actionGroupId + "link-";
        }

        if (view.equals("details")) {
            actionGroupId = actionGroupId + "details";
        } else {
            actionGroupId = actionGroupId + "browse";
        }

        return actionGroupId;
    }
}
