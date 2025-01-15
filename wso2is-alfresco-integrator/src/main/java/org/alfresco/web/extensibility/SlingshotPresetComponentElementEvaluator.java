//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotPresetComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public static final String SITE_PRESET_FILTER = "sitePresets";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotPresetComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String siteId = this.util.getSite(context);
        if (siteId != null) {
            String sitePreset = this.util.getSitePreset(context, siteId);
            if (sitePreset != null && sitePreset.matches(this.util.getEvaluatorParam(params, "sitePresets", ".*"))) {
                return true;
            }
        }

        return false;
    }
}
