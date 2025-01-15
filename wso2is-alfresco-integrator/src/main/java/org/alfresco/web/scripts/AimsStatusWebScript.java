//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.HashMap;
import java.util.Map;
import org.alfresco.web.site.servlet.config.AIMSConfig;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class AimsStatusWebScript extends DeclarativeWebScript implements ApplicationContextAware {
    private ApplicationContext context;

    public AimsStatusWebScript() {
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context = applicationContext;
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap();
        AIMSConfig config = (AIMSConfig)this.context.getBean("aims.config");
        model.put("aimsEnabled", config.isEnabled());
        return model;
    }
}
