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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.ConfigException;

public class FormField {
    private static final String ATTR_LABEL_ID = "label-id";
    private static final String ATTR_LABEL = "label";
    private static final String ATTR_DESCRIPTION_ID = "description-id";
    private static final String ATTR_DESCRIPTION = "description";
    private static final String ATTR_HELP_TEXT_ID = "help-id";
    private static final String ATTR_HELP_TEXT = "help";
    private static final String ATTR_HELP_ENCODE_HTML = "help-encode-html";
    private static final String ATTR_SET = "set";
    private static final String ATTR_READ_ONLY = "read-only";
    private static final String ATTR_MANDATORY = "mandatory";
    private static final String ATTR_SORTED = "sorted";
    private static Log logger = LogFactory.getLog(FormField.class);
    private final String id;
    private final Map<String, String> attributes;
    private Control associatedControl = new Control();
    private final List<ConstraintHandlerDefinition> constraintDefns = new ArrayList();

    public FormField(String id, Map<String, String> attributes) {
        if (id == null) {
            String msg = "Illegal null field id";
            if (logger.isWarnEnabled()) {
                logger.warn(msg);
            }

            throw new ConfigException(msg);
        } else {
            this.id = id;
            if (attributes == null) {
                attributes = Collections.emptyMap();
            }

            this.attributes = attributes;
        }
    }

    public Control getControl() {
        return this.associatedControl;
    }

    void addConstraintDefinition(String type, String message, String messageId, String validationHandler, String event) {
        Iterator var6 = this.constraintDefns.iterator();

        ConstraintHandlerDefinition constraint;
        do {
            if (!var6.hasNext()) {
                this.constraintDefns.add(new ConstraintHandlerDefinition(type, validationHandler, message, messageId, event));
                return;
            }

            constraint = (ConstraintHandlerDefinition)var6.next();
        } while(!constraint.getType().equals(type));

        constraint.setMessage(message);
        constraint.setMessageId(messageId);
        constraint.setValidationHandler(validationHandler);
        constraint.setEvent(event);
    }

    public Map<String, String> getAttributes() {
        return Collections.unmodifiableMap(this.attributes);
    }

    public String getId() {
        return this.id;
    }

    public String getLabel() {
        return (String)this.attributes.get("label");
    }

    public String getLabelId() {
        return (String)this.attributes.get("label-id");
    }

    public String getDescription() {
        return (String)this.attributes.get("description");
    }

    public String getDescriptionId() {
        return (String)this.attributes.get("description-id");
    }

    public boolean isReadOnly() {
        Object disabledValue = this.attributes.get("read-only");
        return disabledValue instanceof String && "true".equalsIgnoreCase((String)disabledValue);
    }

    public boolean isMandatory() {
        Object mandatoryValue = this.attributes.get("mandatory");
        return mandatoryValue instanceof String && "true".equalsIgnoreCase((String)mandatoryValue);
    }

    public boolean isSorted() {
        Object sortedValue = this.attributes.get("sorted");
        return sortedValue instanceof String && "true".equalsIgnoreCase((String)sortedValue);
    }

    public String getSet() {
        String setId = (String)this.attributes.get("set");
        return setId != null ? setId : "";
    }

    public String getHelpText() {
        return (String)this.attributes.get("help");
    }

    public String getHelpTextId() {
        return (String)this.attributes.get("help-id");
    }

    public String getHelpEncodeHtml() {
        return (String)this.attributes.get("help-encode-html");
    }

    public Map<String, ConstraintHandlerDefinition> getConstraintDefinitionMap() {
        Map<String, ConstraintHandlerDefinition> defns = new LinkedHashMap(4);
        Iterator var2 = this.constraintDefns.iterator();

        while(var2.hasNext()) {
            ConstraintHandlerDefinition defn = (ConstraintHandlerDefinition)var2.next();
            defns.put(defn.getType(), defn);
        }

        return Collections.unmodifiableMap(defns);
    }

    public FormField combine(FormField otherField) {
        StringBuilder msg;
        if (logger.isDebugEnabled()) {
            msg = new StringBuilder();
            msg.append("Combining instances of ").append(this);
            logger.debug(msg.toString());
        }

        if (!this.id.equals(otherField.id)) {
            if (logger.isWarnEnabled()) {
                msg = new StringBuilder();
                msg.append("Illegal attempt to combine two FormFields with different IDs: ").append(this.id).append(", ").append(otherField.id);
                logger.warn(msg.toString());
            }

            return this;
        } else {
            Map<String, String> combinedAttributes = new LinkedHashMap();
            combinedAttributes.putAll(this.attributes);
            combinedAttributes.putAll(otherField.attributes);
            FormField result = new FormField(this.id, combinedAttributes);
            Control combinedControl = this.associatedControl.combine(otherField.associatedControl);
            result.associatedControl = combinedControl;
            Iterator var5 = this.constraintDefns.iterator();

            ConstraintHandlerDefinition constraint;
            while(var5.hasNext()) {
                constraint = (ConstraintHandlerDefinition)var5.next();
                result.addConstraintDefinition(constraint.getType(), constraint.getMessage(), constraint.getMessageId(), constraint.getValidationHandler(), constraint.getEvent());
            }

            var5 = otherField.constraintDefns.iterator();

            while(var5.hasNext()) {
                constraint = (ConstraintHandlerDefinition)var5.next();
                result.addConstraintDefinition(constraint.getType(), constraint.getMessage(), constraint.getMessageId(), constraint.getValidationHandler(), constraint.getEvent());
            }

            return result;
        }
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append("FormField:").append(this.id);
        return result.toString();
    }
}
