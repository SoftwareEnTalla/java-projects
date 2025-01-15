//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.web.config.packaging.ModulePackage;
import org.alfresco.web.config.packaging.ModulePackageHelper;
import org.alfresco.web.config.packaging.ModulePackageManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class ModulePackageWebScript extends DeclarativeWebScript {
    private static Log logger = LogFactory.getLog(ModulePackageWebScript.class);
    private ModulePackageManager moduleManager;

    public ModulePackageWebScript() {
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = new HashMap();
        model.put("modulepackages", this.asMap(this.moduleManager.getModulePackages()));
        return model;
    }

    private List<Map> asMap(List<ModulePackage> mp) {
        List<Map> modulesPacks = new ArrayList();
        if (mp != null && !mp.isEmpty()) {
            Iterator var3 = mp.iterator();

            while(var3.hasNext()) {
                ModulePackage modulePackage = (ModulePackage)var3.next();
                modulesPacks.add(ModulePackageHelper.toMap(modulePackage));
            }
        }

        return modulesPacks;
    }

    public void setModuleManager(ModulePackageManager moduleManager) {
        this.moduleManager = moduleManager;
    }
}
