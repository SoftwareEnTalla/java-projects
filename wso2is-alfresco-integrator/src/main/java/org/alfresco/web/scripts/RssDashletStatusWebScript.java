//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class RssDashletStatusWebScript extends DeclarativeWebScript implements ApplicationContextAware {
    private static final String RSSDASHLET_ENABLED = "rssdashlet.enabled";
    private static final String SHOW_DASHLET = "showDashlet";
    private ApplicationContext context;

    public RssDashletStatusWebScript() {
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context = applicationContext;
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap();
        boolean rssDashletStatus = Boolean.parseBoolean(System.getProperty("rssdashlet.enabled"));
        model.put("showDashlet", rssDashletStatus);
        return model;
    }
}
