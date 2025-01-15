//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotUserAgentComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public static final String USERAGENT_FILTER = "useragent";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotUserAgentComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String userAgent = this.util.getHeader("user-agent");
        if (userAgent != null) {
            Pattern p = Pattern.compile(this.util.getEvaluatorParam(params, "useragent", ".*"));
            Matcher m = p.matcher(userAgent);
            return m.find();
        } else {
            return false;
        }
    }
}
