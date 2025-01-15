//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.Iterator;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

class ConstraintHandlersElementReader implements ConfigElementReader {
    public static final String ELEMENT_CONSTRAINT_HANDLERS = "constraint-handlers";
    public static final String ATTR_TYPE = "type";
    public static final String ATTR_VALIDATOR_HANDLER = "validation-handler";
    public static final String ATTR_MESSAGE = "message";
    public static final String ATTR_MESSAGE_ID = "message-id";
    public static final String ATTR_EVENT = "event";

    ConstraintHandlersElementReader() {
    }

    public ConfigElement parse(Element element) {
        ConstraintHandlersConfigElement result = null;
        if (element == null) {
            return null;
        } else {
            String name = element.getName();
            if (!name.equals("constraint-handlers")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse constraint-handlers elements, the element passed was '" + name + "'");
            } else {
                result = new ConstraintHandlersConfigElement();
                Iterator<Element> xmlNodes = element.elementIterator();

                while(xmlNodes.hasNext()) {
                    Element nextNode = (Element)xmlNodes.next();
                    String type = nextNode.attributeValue("type");
                    String validationHandler = nextNode.attributeValue("validation-handler");
                    String message = nextNode.attributeValue("message");
                    String messageId = nextNode.attributeValue("message-id");
                    String event = nextNode.attributeValue("event");
                    result.addDataMapping(type, validationHandler, message, messageId, event);
                }

                return result;
            }
        }
    }
}
