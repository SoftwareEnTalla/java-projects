//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotPageContextComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public static final String PAGE_CONTEXT_FILTER = "pagecontext";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotPageContextComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String pageContext = this.util.getPageContext(context);
        return pageContext != null && pageContext.matches(this.util.getEvaluatorParam(params, "pagecontext", ".*"));
    }
}
