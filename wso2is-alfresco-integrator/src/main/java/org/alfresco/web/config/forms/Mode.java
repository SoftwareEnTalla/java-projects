//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public enum Mode {
    VIEW,
    EDIT,
    CREATE;

    private static Log logger = LogFactory.getLog(Mode.class);

    private Mode() {
    }

    public String toString() {
        return super.toString().toLowerCase();
    }

    public static Mode modeFromString(String modeString) {
        if ("create".equalsIgnoreCase(modeString)) {
            return CREATE;
        } else if ("edit".equalsIgnoreCase(modeString)) {
            return EDIT;
        } else if ("view".equalsIgnoreCase(modeString)) {
            return VIEW;
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Illegal modeString: " + modeString);
            }

            return null;
        }
    }

    public static List<Mode> modesFromString(String commaSeparatedModesString) {
        if (commaSeparatedModesString == null) {
            return Collections.emptyList();
        } else {
            List<Mode> result = new ArrayList();
            StringTokenizer st = new StringTokenizer(commaSeparatedModesString, ",");

            while(st.hasMoreTokens()) {
                String nextToken = st.nextToken().trim();
                Mode nextMode = modeFromString(nextToken);
                result.add(nextMode);
            }

            return result;
        }
    }
}
