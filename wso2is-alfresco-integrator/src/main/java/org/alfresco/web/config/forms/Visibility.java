//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public enum Visibility {
    SHOW,
    HIDE;

    private static Log logger = LogFactory.getLog(Visibility.class);

    private Visibility() {
    }

    public static Visibility visibilityFromString(String visibilityString) {
        if (visibilityString.equalsIgnoreCase("show")) {
            return SHOW;
        } else if (visibilityString.equalsIgnoreCase("hide")) {
            return HIDE;
        } else {
            if (logger.isDebugEnabled()) {
                StringBuilder msg = new StringBuilder();
                msg.append("Illegal visibilityString: ").append(visibilityString);
                logger.debug(msg.toString());
            }

            return null;
        }
    }
}
