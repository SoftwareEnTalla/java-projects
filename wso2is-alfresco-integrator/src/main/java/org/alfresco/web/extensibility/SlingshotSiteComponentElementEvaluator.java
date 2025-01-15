//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotSiteComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public static final String SITE_FILTER = "sites";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotSiteComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String siteId = this.util.getSite(context);
        return siteId != null && siteId.matches(this.util.getEvaluatorParam(params, "sites", ".*"));
    }
}
