//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONObject;

public class IsBrowserEvaluator extends BaseEvaluator {
    private String regex;

    public IsBrowserEvaluator() {
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.regex == null) {
            return false;
        } else {
            try {
                String userAgent = this.getHeader("user-agent");
                if (userAgent != null) {
                    Pattern p = Pattern.compile(this.regex);
                    Matcher m = p.matcher(userAgent);
                    return m.find();
                } else {
                    return false;
                }
            } catch (Exception var5) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var5.getMessage());
            }
        }
    }
}
