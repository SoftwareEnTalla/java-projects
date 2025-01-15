//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.alfresco.web.scripts.DictionaryQuery;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptRequest;

public class CMMDictionaryGet extends DeclarativeWebScript {
    private static final Log logger = LogFactory.getLog(CMMDictionaryGet.class);
    protected DictionaryQuery dictionary;

    public CMMDictionaryGet() {
    }

    public void setDictionary(DictionaryQuery dictionary) {
        this.dictionary = dictionary;
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> result = new HashMap();
        String[] classes = null;
        String entity = (String)req.getServiceMatch().getTemplateVars().get("entity");
        if (entity != null && entity.length() != 0) {
            classes = this.dictionary.getSubTypes(entity);
        } else {
            String classtype = (String)req.getServiceMatch().getTemplateVars().get("classtype");
            if (classtype != null) {
                switch (classtype) {
                    case "aspects":
                        classes = this.dictionary.getAllAspects();
                        break;
                    case "types":
                        classes = this.dictionary.getAllTypes();
                }
            }
        }

        if (classes == null) {
            throw new IllegalArgumentException("No valid entity or types/aspects modifier specified.");
        } else {
            List<CMMService.TWrapper> entities = new ArrayList();
            String[] var8 = classes;
            int var9 = classes.length;

            for(int var10 = 0; var10 < var9; ++var10) {
                String e = var8[var10];
                entities.add((new CMMService.TWrapper(4)).put("name", e).put("title", this.dictionary.getTitle(e)).put("description", this.dictionary.getDescription(e)));
            }

            result.put("entities", entities);
            return result;
        }
    }
}
