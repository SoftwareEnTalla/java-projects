//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class ConstraintHandlersConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = 2266042608444782740L;
    public static final String CONFIG_ELEMENT_ID = "constraint-handlers";
    private Map<String, ConstraintHandlerDefinition> items = new LinkedHashMap();

    public ConstraintHandlersConfigElement() {
        super("constraint-handlers");
    }

    public ConstraintHandlersConfigElement(String name) {
        super(name);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the constraint-handlers config via the generic interfaces is not supported");
    }

    public ConfigElement combine(ConfigElement configElement) {
        if (configElement == null) {
            return this;
        } else {
            ConstraintHandlersConfigElement otherCHCElement = (ConstraintHandlersConfigElement)configElement;
            ConstraintHandlersConfigElement result = new ConstraintHandlersConfigElement();
            Iterator var4 = this.items.keySet().iterator();

            String nextType;
            String nextValidationHandler;
            String nextMessage;
            String nextMessageId;
            String nextEvent;
            while(var4.hasNext()) {
                nextType = (String)var4.next();
                nextValidationHandler = this.getValidationHandlerFor(nextType);
                nextMessage = this.getMessageFor(nextType);
                nextMessageId = this.getMessageIdFor(nextType);
                nextEvent = this.getEventFor(nextType);
                result.addDataMapping(nextType, nextValidationHandler, nextMessage, nextMessageId, nextEvent);
            }

            var4 = otherCHCElement.items.keySet().iterator();

            while(var4.hasNext()) {
                nextType = (String)var4.next();
                nextValidationHandler = otherCHCElement.getValidationHandlerFor(nextType);
                nextMessage = otherCHCElement.getMessageFor(nextType);
                nextMessageId = otherCHCElement.getMessageIdFor(nextType);
                nextEvent = otherCHCElement.getEventFor(nextType);
                result.addDataMapping(nextType, nextValidationHandler, nextMessage, nextMessageId, nextEvent);
            }

            return result;
        }
    }

    void addDataMapping(String type, String validationHandler, String message, String messageID, String event) {
        this.items.put(type, new ConstraintHandlerDefinition(type, validationHandler, message, messageID, event));
    }

    String[] getConstraintTypes() {
        return (String[])this.getConstraintTypesAsList().toArray(new String[0]);
    }

    List<String> getConstraintTypesAsList() {
        Set<String> result = this.items.keySet();
        List<String> listResult = new ArrayList(result);
        return Collections.unmodifiableList(listResult);
    }

    String getValidationHandlerFor(String type) {
        return ((ConstraintHandlerDefinition)this.items.get(type)).getValidationHandler();
    }

    String getMessageFor(String type) {
        return ((ConstraintHandlerDefinition)this.items.get(type)).getMessage();
    }

    String getMessageIdFor(String type) {
        return ((ConstraintHandlerDefinition)this.items.get(type)).getMessageId();
    }

    String getEventFor(String type) {
        return ((ConstraintHandlerDefinition)this.items.get(type)).getEvent();
    }

    public String[] getItemNames() {
        return (String[])this.getItemNamesAsList().toArray(new String[0]);
    }

    public List<String> getItemNamesAsList() {
        return this.getConstraintTypesAsList();
    }

    public Map<String, ConstraintHandlerDefinition> getItems() {
        return Collections.unmodifiableMap(this.items);
    }
}
