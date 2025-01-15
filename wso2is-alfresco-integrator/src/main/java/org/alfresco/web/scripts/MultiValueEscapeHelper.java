//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.ArrayList;
import java.util.List;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public class MultiValueEscapeHelper extends BaseProcessorExtension {
    public MultiValueEscapeHelper() {
    }

    public List<String> getUnescapedValues(String escapedString) {
        List<String> elements = new ArrayList();
        StringBuffer currentElement = new StringBuffer();
        boolean isEscaped = false;

        for(int i = 0; i < escapedString.length(); ++i) {
            char currentChar = escapedString.charAt(i);
            if (isEscaped) {
                isEscaped = false;
                currentElement.append(currentChar);
            } else if (currentChar == '\\') {
                isEscaped = true;
            } else if (currentChar == ',') {
                elements.add(currentElement.toString());
                currentElement.delete(0, currentElement.length());
            } else {
                currentElement.append(currentChar);
            }
        }

        if (currentElement.length() > 0) {
            elements.add(currentElement.toString());
        }

        return elements;
    }
}
