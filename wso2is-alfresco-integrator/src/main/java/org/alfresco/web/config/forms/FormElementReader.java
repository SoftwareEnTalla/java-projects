//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.dom4j.Attribute;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

class FormElementReader implements ConfigElementReader {
    public static final String ATTR_APPEARANCE = "appearance";
    public static final String ATTR_LABEL = "label";
    public static final String ATTR_LABEL_ID = "label-id";
    public static final String ATTR_FOR_MODE = "for-mode";
    public static final String ATTR_FORM_ID = "id";
    public static final String ATTR_MESSAGE = "message";
    public static final String ATTR_MESSAGE_ID = "message-id";
    public static final String ATTR_EVENT = "event";
    public static final String ATTR_VALIDATION_HANDLER = "validation-handler";
    public static final String ATTR_NAME = "name";
    public static final String ATTR_NAME_ID = "id";
    public static final String ATTR_PARENT = "parent";
    public static final String ATTR_SUBMISSION_URL = "submission-url";
    public static final String ATTR_TEMPLATE = "template";
    public static final String ATTR_TYPE = "type";
    public static final String ATTR_FORCE = "force";
    public static final String ELEMENT_FORM = "form";
    public static final String ELEMENT_HIDE = "hide";
    public static final String ELEMENT_SHOW = "show";

    FormElementReader() {
    }

    public ConfigElement parse(Element formElement) {
        FormConfigElement result = null;
        if (formElement == null) {
            return null;
        } else {
            String name = formElement.getName();
            if (!name.equals("form")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse form elements, the element passed was '" + name + "'");
            } else {
                result = new FormConfigElement();
                this.parseFormId(formElement, result);
                this.parseSubmissionURL(formElement, result);
                this.parseFormTag(formElement, result);
                this.parseFieldVisibilityTag(formElement, result);
                this.parseAppearanceTag(formElement, result);
                return result;
            }
        }
    }

    private void parseAppearanceTag(Element formElement, FormConfigElement result) {
        this.parseSetTags(formElement, result);
        this.parseFieldTags(formElement, result);
    }

    private void parseFieldTags(Element formElement, FormConfigElement result) {
        Iterator var3 = formElement.selectNodes("./appearance/field").iterator();

        while(var3.hasNext()) {
            Object fieldObj = var3.next();
            Element fieldElem = (Element)fieldObj;
            List<Attribute> fieldAttributes = new ArrayList();
            Iterator var7 = fieldElem.selectNodes("./@*").iterator();

            while(var7.hasNext()) {
                Object obj = var7.next();
                fieldAttributes.add((Attribute)obj);
            }

            List<String> fieldAttributeNames = new ArrayList();
            List<String> fieldAttributeValues = new ArrayList();
            String fieldIdValue = null;
            Iterator var10 = fieldAttributes.iterator();

            String templateValue;
            while(var10.hasNext()) {
                Attribute nextAttr = (Attribute)var10.next();
                templateValue = nextAttr.getName();
                String nextAttributeValue = nextAttr.getValue();
                if (templateValue.equals("id")) {
                    fieldIdValue = nextAttributeValue;
                } else {
                    fieldAttributeNames.add(templateValue);
                    fieldAttributeValues.add(nextAttributeValue);
                }
            }

            if (fieldIdValue == null) {
                throw new ConfigException("<field> node missing mandatory id attribute.");
            }

            result.addField(fieldIdValue, fieldAttributeNames, fieldAttributeValues);
            List<Element> controlObjs = new ArrayList();
            Iterator var24 = fieldElem.selectNodes("./control").iterator();

            while(var24.hasNext()) {
                Object obj = var24.next();
                controlObjs.add((Element)obj);
            }

            if (!controlObjs.isEmpty()) {
                Element controlElem = (Element)controlObjs.get(0);
                templateValue = controlElem.attributeValue("template");
                List<String> controlParamNames = new ArrayList();
                List<String> controlParamValues = new ArrayList();
                Iterator var15 = controlElem.selectNodes("./control-param").iterator();

                while(var15.hasNext()) {
                    Object paramObj = var15.next();
                    Element paramElem = (Element)paramObj;
                    controlParamNames.add(paramElem.attributeValue("name"));
                    controlParamValues.add(paramElem.getTextTrim());
                }

                result.addControlForField(fieldIdValue, templateValue, controlParamNames, controlParamValues);
            }

            ConstraintHandlersElementReader constraintHandlersElementReader = new ConstraintHandlersElementReader();
            Iterator var28 = fieldElem.selectNodes("./constraint-handlers").iterator();

            while(var28.hasNext()) {
                Object constraintHandlerObj = var28.next();
                Element constraintHandlers = (Element)constraintHandlerObj;
                ConfigElement confElem = constraintHandlersElementReader.parse(constraintHandlers);
                ConstraintHandlersConfigElement constraintHandlerCE = (ConstraintHandlersConfigElement)confElem;
                Map<String, ConstraintHandlerDefinition> constraintItems = constraintHandlerCE.getItems();
                Iterator var18 = constraintItems.keySet().iterator();

                while(var18.hasNext()) {
                    String key = (String)var18.next();
                    ConstraintHandlerDefinition defn = (ConstraintHandlerDefinition)constraintItems.get(key);
                    result.addConstraintForField(fieldIdValue, defn.getType(), defn.getMessage(), defn.getMessageId(), defn.getValidationHandler(), defn.getEvent());
                }
            }
        }

    }

    private void parseSetTags(Element formElement, FormConfigElement result) {
        Iterator var3 = formElement.selectNodes("./appearance/set").iterator();

        while(var3.hasNext()) {
            Object setObj = var3.next();
            Element setElem = (Element)setObj;
            String setId = setElem.attributeValue("id");
            String parentSetId = setElem.attributeValue("parent");
            String appearance = setElem.attributeValue("appearance");
            String label = setElem.attributeValue("label");
            String labelId = setElem.attributeValue("label-id");
            String template = setElem.attributeValue("template");
            result.addSet(setId, parentSetId, appearance, label, labelId, template);
        }

    }

    private void parseFieldVisibilityTag(Element formElement, FormConfigElement result) {
        Iterator var3 = formElement.selectNodes("./field-visibility/show|./field-visibility/hide").iterator();

        while(var3.hasNext()) {
            Object obj = var3.next();
            Element showOrHideElem = (Element)obj;
            String nodeName = showOrHideElem.getName();
            String fieldId = showOrHideElem.attributeValue("id");
            String mode = showOrHideElem.attributeValue("for-mode");
            String forceString = showOrHideElem.attributeValue("force");
            result.addFieldVisibility(nodeName, fieldId, mode, forceString);
        }

    }

    private void parseFormTag(Element formElement, FormConfigElement result) {
        Iterator var3 = formElement.selectNodes("./edit-form|./view-form|./create-form").iterator();

        while(var3.hasNext()) {
            Object obj = var3.next();
            Element editOrViewOrCreateFormElem = (Element)obj;
            String nodeName = editOrViewOrCreateFormElem.getName();
            String template = editOrViewOrCreateFormElem.attributeValue("template");
            result.setFormTemplate(nodeName, template);
        }

    }

    private void parseSubmissionURL(Element formElement, FormConfigElement result) {
        String submissionURL = formElement.attributeValue("submission-url");
        result.setSubmissionURL(submissionURL);
    }

    private void parseFormId(Element formElement, FormConfigElement result) {
        String formId = formElement.attributeValue("id");
        result.setFormId(formId);
    }
}
