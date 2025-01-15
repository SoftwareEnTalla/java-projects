//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator.doclib.action;

import org.alfresco.web.evaluator.BaseEvaluator;
import org.json.simple.JSONObject;
import org.springframework.extensions.config.Config;
import org.springframework.extensions.config.ConfigService;

public class ViewInExplorerEvaluator extends BaseEvaluator {
    private static final String CONFIG_CONDITION_DOCUMENTLIBRARY = "DocumentLibrary";
    private static final String CONFIG_ELEMENT_REPOSITORY_URL = "repository-url";
    private ConfigService configService;

    public ViewInExplorerEvaluator() {
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

    public boolean evaluate(JSONObject jsonObject) {
        return this.getConfigValue("DocumentLibrary", "repository-url") != null && !this.getIsPortlet();
    }

    protected Object getConfigValue(String condition, String elementName) {
        Config config = this.configService.getConfig(condition);
        return config == null ? null : config.getConfigElementValue(elementName);
    }
}
