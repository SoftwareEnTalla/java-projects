//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.Iterator;
import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotEqualsComponentElementEvaluator extends DefaultSubComponentEvaluator {
    public SlingshotEqualsComponentElementEvaluator() {
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        if (params.isEmpty()) {
            return false;
        } else if (params.size() < 2) {
            return false;
        } else {
            String firstValue = (String)params.values().iterator().next();
            if (firstValue == null) {
                firstValue = "";
            }

            Iterator var4 = params.values().iterator();

            String value;
            do {
                if (!var4.hasNext()) {
                    return true;
                }

                value = (String)var4.next();
            } while(firstValue.equals(value));

            return false;
        }
    }
}
