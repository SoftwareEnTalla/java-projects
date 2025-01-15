//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.Config;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotConfigComponentElementEvaluator extends DefaultSubComponentEvaluator {
    private static Log logger = LogFactory.getLog(SlingshotConfigComponentElementEvaluator.class);
    public static final String ELEMENT = "element";
    public static final String MATCH = "match";
    protected SlingshotEvaluatorUtil util = null;
    protected ConfigService configService = null;

    public SlingshotConfigComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        String element = this.util.getEvaluatorParam(params, "element", (String)null);
        if (element != null) {
            String token = null;
            String value = null;
            Config config = null;
            ConfigElement configElement = null;
            String[] tokens = element.split("/");

            int i;
            for(i = 0; i < tokens.length; ++i) {
                token = tokens[i];
                if (!token.isEmpty()) {
                    if (i == 0) {
                        config = this.configService.getConfig(token);
                    } else if (i == 1 && config != null) {
                        value = config.getConfigElementValue(token);
                        configElement = config.getConfigElement(token);
                    } else if (i >= 2 && configElement != null) {
                        value = configElement.getChildValue(token);
                        configElement = configElement.getChild(token);
                    }
                }
            }

            if (value != null && i == tokens.length) {
                String match = this.util.getEvaluatorParam(params, "match", (String)null);
                if (match != null) {
                    return match.matches(value);
                }

                return value.equalsIgnoreCase("true");
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Could not find value for <element>" + element + "</element>");
            }
        }

        return false;
    }
}
