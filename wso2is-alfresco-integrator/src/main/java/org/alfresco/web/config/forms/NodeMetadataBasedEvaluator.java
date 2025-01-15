//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.extensions.surf.exception.ConnectorServiceException;

public abstract class NodeMetadataBasedEvaluator extends ServiceBasedEvaluator {
    protected static final Pattern nodeRefPattern = Pattern.compile(".+://.+/.+");

    public NodeMetadataBasedEvaluator() {
    }

    protected abstract boolean checkJsonAgainstCondition(String var1, String var2);

    public boolean applies(Object obj, String condition) {
        boolean result = false;
        if (obj instanceof String objAsString) {
            if (objAsString.indexOf(58) != -1) {
                Matcher m = nodeRefPattern.matcher(objAsString);
                if (m.matches()) {
                    try {
                        String jsonResponseString = this.callMetadataService(objAsString);
                        if (jsonResponseString != null) {
                            result = this.checkJsonAgainstCondition(condition, jsonResponseString);
                        } else if (this.getLogger().isWarnEnabled()) {
                            this.getLogger().warn("Metadata service response appears to be null!");
                        }
                    } catch (ServiceBasedEvaluator.NotAuthenticatedException var7) {
                    } catch (ConnectorServiceException var8) {
                        if (this.getLogger().isWarnEnabled()) {
                            this.getLogger().warn("Failed to connect to metadata service.", var8);
                        }
                    }
                }
            }
        }

        return result;
    }

    protected String callMetadataService(String nodeString) throws ConnectorServiceException {
        return this.callService("/api/metadata?nodeRef=" + nodeString + "&shortQNames=true");
    }
}
