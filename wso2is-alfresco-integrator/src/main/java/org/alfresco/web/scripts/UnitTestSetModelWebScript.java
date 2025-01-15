//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.servlet.WebScriptServletRequest;

public class UnitTestSetModelWebScript extends DeclarativeWebScript {
    public UnitTestSetModelWebScript() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap(7, 1.0F);

        try {
            try {
                String content = req.getContent().getContent();
                JSONParser jp = new JSONParser();
                Object o = jp.parse(content);
                if (o instanceof JSONObject jsonData) {
                    String jsonModel = (String)jsonData.get("unitTestModel");
                    if (jsonModel != null) {
                        HttpServletRequest httpRequest = ((WebScriptServletRequest)req).getHttpServletRequest();
                        HttpSession httpSession = httpRequest.getSession();
                        httpSession.setAttribute("unitTestModel", jsonModel);
                        model.put("result", "SUCCESS");
                    } else {
                        model.put("result", "MISSING MODEL");
                    }
                }
            } catch (IOException var16) {
                model.put("result", "IO Exception: " + var16.getLocalizedMessage());
            } catch (ParseException var17) {
                model.put("result", "ParseException: " + var17.getLocalizedMessage());
            }

            return model;
        } finally {
            ;
        }
    }
}
