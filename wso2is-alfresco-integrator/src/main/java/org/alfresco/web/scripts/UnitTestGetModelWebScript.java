//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import jakarta.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class UnitTestGetModelWebScript extends DeclarativeWebScript {
    public UnitTestGetModelWebScript() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap(7, 1.0F);
        HttpSession httpSession = ServletUtil.getSession(false);
        if (httpSession != null) {
            String jsonModel = (String)httpSession.getAttribute("unitTestModel");
            model.put("jsonModel", jsonModel);
        }

        return model;
    }
}
