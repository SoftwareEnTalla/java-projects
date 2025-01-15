//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.HashMap;
import java.util.Map;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class StripLinkedNodePropertiesOption extends DeclarativeWebScript {
    private static final String STRIP_LINKED_NODE_PROPS = "strip.linked-node.properties";

    public StripLinkedNodePropertiesOption() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap();
        boolean stripLinkedNodeProperties = Boolean.parseBoolean(System.getProperty("strip.linked-node.properties"));
        model.put("stripLinkedNodeProperties", stripLinkedNodeProperties);
        return model;
    }
}
