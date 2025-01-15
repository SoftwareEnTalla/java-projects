//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotPageComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public static final String PAGE_FILTER = "pages";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotPageComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String pageId = this.util.getPageId(context);
        return pageId != null && pageId.matches(this.util.getEvaluatorParam(params, "pages", ".*"));
    }
}
