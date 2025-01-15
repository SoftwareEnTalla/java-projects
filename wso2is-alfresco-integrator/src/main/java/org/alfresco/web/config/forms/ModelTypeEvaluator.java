//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import org.springframework.extensions.config.evaluator.Evaluator;

public class ModelTypeEvaluator implements Evaluator {
    public ModelTypeEvaluator() {
    }

    public boolean applies(Object obj, String condition) {
        boolean result = false;
        if (obj instanceof String && condition.equalsIgnoreCase((String)obj)) {
            result = true;
        }

        return result;
    }
}
