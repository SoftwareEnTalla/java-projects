//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class FormConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = -7008510360503886308L;
    private static Log logger = LogFactory.getLog(FormConfigElement.class);
    public static final String FORM_NAME_ID = "form";
    public static final String DEFAULT_SET_ID = "";
    private String formId;
    private String submissionURL;
    private String createTemplate;
    private String editTemplate;
    private String viewTemplate;
    FieldVisibilityManager fieldVisibilityManager;
    private final Map<String, FormSet> sets;
    private Map<String, FormField> fields;
    private List<String> forcedFields;

    public FormConfigElement() {
        this("form");
    }

    public FormConfigElement(String name) {
        super(name);
        this.fieldVisibilityManager = new FieldVisibilityManager();
        this.sets = new LinkedHashMap(4);
        this.fields = new LinkedHashMap(8);
        this.forcedFields = new ArrayList(4);
        FormSet defaultSet = new FormSet("");
        this.sets.put("", defaultSet);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the form config via the generic interfaces is not supported");
    }

    public ConfigElement combine(ConfigElement otherConfigElement) {
        if (otherConfigElement == null) {
            return this;
        } else {
            FormConfigElement otherFormElem = (FormConfigElement)otherConfigElement;
            FormConfigElement result = new FormConfigElement();
            this.combineSubmissionURL(otherFormElem, result);
            this.combineTemplates(otherFormElem, result);
            this.combineFieldVisibilities(otherFormElem, result);
            this.combineSets(otherFormElem, result);
            this.combineFields(otherFormElem, result);
            return result;
        }
    }

    private void combineFields(FormConfigElement otherFormElem, FormConfigElement result) {
        Map<String, FormField> newFields = new LinkedHashMap();
        Iterator var4 = this.fields.keySet().iterator();

        String fieldName;
        while(var4.hasNext()) {
            fieldName = (String)var4.next();
            FormField nextFieldFromThis = (FormField)this.fields.get(fieldName);
            if (otherFormElem.getFields().containsKey(fieldName)) {
                FormField combinedField = nextFieldFromThis.combine((FormField)otherFormElem.getFields().get(fieldName));
                newFields.put(fieldName, combinedField);
            } else {
                newFields.put(fieldName, nextFieldFromThis);
            }
        }

        var4 = otherFormElem.fields.keySet().iterator();

        while(var4.hasNext()) {
            fieldName = (String)var4.next();
            if (!this.fields.containsKey(fieldName)) {
                newFields.put(fieldName, (FormField)otherFormElem.fields.get(fieldName));
            }
        }

        result.setFields(newFields);
        result.forcedFields.addAll(this.forcedFields);
        var4 = otherFormElem.forcedFields.iterator();

        while(var4.hasNext()) {
            fieldName = (String)var4.next();
            if (!result.forcedFields.contains(fieldName)) {
                result.forcedFields.add(fieldName);
            }
        }

    }

    private void combineSets(FormConfigElement otherFormElem, FormConfigElement result) {
        Iterator var3 = this.sets.keySet().iterator();

        String nextNewSet;
        FormSet nextNewSetData;
        String setId;
        String parentId;
        String appearance;
        String label;
        String labelId;
        String template;
        while(var3.hasNext()) {
            nextNewSet = (String)var3.next();
            nextNewSetData = (FormSet)this.sets.get(nextNewSet);
            setId = nextNewSetData.getSetId();
            parentId = nextNewSetData.getParentId();
            appearance = nextNewSetData.getAppearance();
            label = nextNewSetData.getLabel();
            labelId = nextNewSetData.getLabelId();
            template = nextNewSetData.getTemplate();
            result.addSet(setId, parentId, appearance, label, labelId, template);
        }

        var3 = otherFormElem.sets.keySet().iterator();

        while(var3.hasNext()) {
            nextNewSet = (String)var3.next();
            nextNewSetData = (FormSet)otherFormElem.sets.get(nextNewSet);
            setId = nextNewSetData.getSetId();
            parentId = nextNewSetData.getParentId();
            appearance = nextNewSetData.getAppearance();
            label = nextNewSetData.getLabel();
            labelId = nextNewSetData.getLabelId();
            template = nextNewSetData.getTemplate();
            result.addSet(setId, parentId, appearance, label, labelId, template);
        }

    }

    private void combineFieldVisibilities(FormConfigElement otherFormElem, FormConfigElement result) {
        FieldVisibilityManager combinedManager = this.fieldVisibilityManager.combine(otherFormElem.fieldVisibilityManager);
        result.fieldVisibilityManager = combinedManager;
    }

    private void combineTemplates(FormConfigElement otherFormElem, FormConfigElement result) {
        result.setFormTemplate("create-form", otherFormElem.createTemplate == null ? this.createTemplate : otherFormElem.createTemplate);
        result.setFormTemplate("edit-form", otherFormElem.editTemplate == null ? this.editTemplate : otherFormElem.editTemplate);
        result.setFormTemplate("view-form", otherFormElem.viewTemplate == null ? this.viewTemplate : otherFormElem.viewTemplate);
    }

    private void combineSubmissionURL(FormConfigElement otherFormElem, FormConfigElement result) {
        String otherSubmissionURL = otherFormElem.getSubmissionURL();
        result.setSubmissionURL(otherSubmissionURL == null ? this.submissionURL : otherSubmissionURL);
    }

    public String getId() {
        return this.formId;
    }

    public String getSubmissionURL() {
        return this.submissionURL;
    }

    public Map<String, FormSet> getSets() {
        return Collections.unmodifiableMap(this.sets);
    }

    public String[] getSetIDs() {
        return (String[])this.getSetIDsAsList().toArray(new String[0]);
    }

    public List<String> getSetIDsAsList() {
        Set<String> keySet = this.sets.keySet();
        List<String> result = new ArrayList(keySet.size());
        result.addAll(keySet);
        return Collections.unmodifiableList(result);
    }

    public FormSet[] getRootSets() {
        return (FormSet[])this.getRootSetsAsList().toArray(new FormSet[0]);
    }

    public List<FormSet> getRootSetsAsList() {
        List<FormSet> result = new ArrayList(this.sets.size());
        Iterator<String> iter = this.sets.keySet().iterator();

        while(iter.hasNext()) {
            String nextKey = (String)iter.next();
            FormSet nextSet = (FormSet)this.sets.get(nextKey);
            String nextParentID = nextSet.getParentId();
            if (nextParentID == null) {
                result.add(nextSet);
            }
        }

        return result;
    }

    public Map<String, FormField> getFields() {
        Set<String> fieldsVisibleInAnyMode = new LinkedHashSet();
        Mode[] var2 = Mode.values();
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            Mode m = var2[var4];
            List<String> newFields = this.fieldVisibilityManager.getFieldNamesVisibleInMode(m);
            if (newFields != null) {
                fieldsVisibleInAnyMode.addAll(newFields);
            }
        }

        Map<String, FormField> result = new LinkedHashMap();
        result.putAll(this.fields);
        Iterator var8 = fieldsVisibleInAnyMode.iterator();

        while(var8.hasNext()) {
            String s = (String)var8.next();
            if (!result.containsKey(s)) {
                result.put(s, new FormField(s, (Map)null));
            }
        }

        return Collections.unmodifiableMap(result);
    }

    public String[] getHiddenCreateFieldNames() {
        List<String> names = this.getHiddenCreateFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public String[] getHiddenEditFieldNames() {
        List<String> names = this.getHiddenEditFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public String[] getHiddenViewFieldNames() {
        List<String> names = this.getHiddenViewFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public String[] getVisibleCreateFieldNames() {
        List<String> names = this.getVisibleCreateFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public String[] getVisibleEditFieldNames() {
        List<String> names = this.getVisibleEditFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public String[] getVisibleViewFieldNames() {
        List<String> names = this.getVisibleViewFieldNamesAsList();
        return names != null ? (String[])names.toArray(new String[0]) : null;
    }

    public List<String> getHiddenCreateFieldNamesAsList() {
        return this.getFieldNamesHiddenInMode(Mode.CREATE);
    }

    public List<String> getHiddenEditFieldNamesAsList() {
        return this.getFieldNamesHiddenInMode(Mode.EDIT);
    }

    public List<String> getHiddenViewFieldNamesAsList() {
        return this.getFieldNamesHiddenInMode(Mode.VIEW);
    }

    public List<String> getVisibleCreateFieldNamesAsList() {
        return this.getFieldNamesVisibleInMode(Mode.CREATE);
    }

    public List<String> getVisibleEditFieldNamesAsList() {
        return this.getFieldNamesVisibleInMode(Mode.EDIT);
    }

    public List<String> getVisibleViewFieldNamesAsList() {
        return this.getFieldNamesVisibleInMode(Mode.VIEW);
    }

    public List<String> getVisibleCreateFieldNamesForSetAsList(String setId) {
        return this.getVisibleFieldNamesFor(setId, Mode.CREATE);
    }

    public String[] getVisibleCreateFieldNamesForSet(String setId) {
        List<String> result = this.getVisibleCreateFieldNamesForSetAsList(setId);
        return result == null ? null : (String[])result.toArray(new String[0]);
    }

    public List<String> getVisibleEditFieldNamesForSetAsList(String setId) {
        return this.getVisibleFieldNamesFor(setId, Mode.EDIT);
    }

    public String[] getVisibleEditFieldNamesForSet(String setId) {
        List<String> result = this.getVisibleEditFieldNamesForSetAsList(setId);
        return result == null ? null : (String[])result.toArray(new String[0]);
    }

    public List<String> getVisibleViewFieldNamesForSetAsList(String setId) {
        return this.getVisibleFieldNamesFor(setId, Mode.VIEW);
    }

    public String[] getVisibleViewFieldNamesForSet(String setId) {
        List<String> result = this.getVisibleViewFieldNamesForSetAsList(setId);
        return result == null ? null : (String[])result.toArray(new String[0]);
    }

    private List<String> getVisibleFieldNamesFor(String setId, Mode mode) {
        List<String> result = new ArrayList();
        FormSet specifiedSet = (FormSet)this.getSets().get(setId);
        if (specifiedSet == null) {
            return null;
        } else {
            List<String> visibleFields = this.getFieldNamesVisibleInMode(mode);
            if (visibleFields == null) {
                return null;
            } else {
                Iterator var6 = visibleFields.iterator();

                while(var6.hasNext()) {
                    String fieldName = (String)var6.next();
                    FormField appearanceField = (FormField)this.fields.get(fieldName);
                    FormField formField = appearanceField != null ? appearanceField : new FormField(fieldName, (Map)null);
                    String set = null;
                    if (formField != null) {
                        set = formField.getSet();
                    }

                    if (set == null) {
                        set = "";
                    }

                    if (set.equals(setId)) {
                        result.add(fieldName);
                    }
                }

                return result;
            }
        }
    }

    public String getCreateTemplate() {
        return this.createTemplate;
    }

    public String getEditTemplate() {
        return this.editTemplate;
    }

    public String getViewTemplate() {
        return this.viewTemplate;
    }

    void setFormId(String formId) {
        this.formId = formId;
    }

    public String getFormTemplate(Mode m) {
        switch (m) {
            case CREATE:
                return this.getCreateTemplate();
            case EDIT:
                return this.getEditTemplate();
            case VIEW:
                return this.getViewTemplate();
            default:
                return null;
        }
    }

    public boolean isFieldVisible(String fieldId, Mode m) {
        return this.fieldVisibilityManager.isFieldVisible(fieldId, m);
    }

    public boolean isFieldHidden(String fieldId, Mode m) {
        return this.fieldVisibilityManager.isFieldHidden(fieldId, m);
    }

    public boolean isFieldVisibleInMode(String fieldId, String modeString) {
        Mode m = Mode.modeFromString(modeString);
        return this.isFieldVisible(fieldId, m);
    }

    public boolean isFieldHiddenInMode(String fieldId, String modeString) {
        Mode m = Mode.modeFromString(modeString);
        return this.isFieldHidden(fieldId, m);
    }

    public boolean isFieldForced(String fieldId) {
        return this.forcedFields.contains(fieldId);
    }

    public String[] getForcedFields() {
        return (String[])this.getForcedFieldsAsList().toArray(new String[0]);
    }

    public List<String> getForcedFieldsAsList() {
        return this.forcedFields;
    }

    private List<String> getFieldNamesHiddenInMode(Mode mode) {
        List<String> result = this.fieldVisibilityManager.getFieldNamesHiddenInMode(mode);
        return result;
    }

    private List<String> getFieldNamesVisibleInMode(Mode mode) {
        List<String> result = this.fieldVisibilityManager.getFieldNamesVisibleInMode(mode);
        return result;
    }

    void setSubmissionURL(String newURL) {
        this.submissionURL = newURL;
    }

    void setFormTemplate(String nodeName, String newTemplate) {
        if (nodeName.equals("create-form")) {
            this.createTemplate = newTemplate;
        } else if (nodeName.equals("edit-form")) {
            this.editTemplate = newTemplate;
        } else {
            if (!nodeName.equals("view-form")) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Unrecognised mode: " + nodeName);
                }

                return;
            }

            this.viewTemplate = newTemplate;
        }

    }

    void addFieldVisibility(String showOrHide, String fieldId, String mode, String forceString) {
        this.fieldVisibilityManager.addInstruction(showOrHide, fieldId, mode);
        boolean isForced = new Boolean(forceString);
        if (isForced && !this.forcedFields.contains(fieldId)) {
            this.forcedFields.add(fieldId);
        }

    }

    void addSet(String setId, String parentSetId, String appearance, String label, String labelId) {
        this.addSet(setId, parentSetId, appearance, label, labelId, (String)null);
    }

    void addSet(String setId, String parentSetId, String appearance, String label, String labelId, String template) {
        FormSet newFormSetObject = new FormSet(setId, parentSetId, appearance, label, labelId, template);
        StringBuilder errorMsg;
        if (parentSetId != null && !this.sets.containsKey(parentSetId)) {
            errorMsg = new StringBuilder();
            errorMsg.append("Set [").append(setId).append("] has undefined parent [").append(parentSetId).append("].");
            throw new ConfigException(errorMsg.toString());
        } else if (setId.equals("") && parentSetId != null) {
            errorMsg = new StringBuilder();
            errorMsg.append("Default set cannot have any parent set. Parent specified was: [").append(parentSetId).append("].");
            throw new ConfigException(errorMsg.toString());
        } else {
            this.sets.put(setId, newFormSetObject);
            if (parentSetId != null) {
                FormSet parentObject = (FormSet)this.sets.get(parentSetId);
                newFormSetObject.setParent(parentObject);
                parentObject.addChild(newFormSetObject);
            }

        }
    }

    void addField(String fieldId, List<String> attributeNames, List<String> attributeValues) {
        if (attributeNames == null) {
            attributeNames = Collections.emptyList();
        }

        if (attributeValues == null) {
            attributeValues = Collections.emptyList();
        }

        if (attributeNames.size() < attributeValues.size() && logger.isWarnEnabled()) {
            StringBuilder msg = new StringBuilder();
            msg.append("field ").append(fieldId).append(" has ").append(attributeNames.size()).append(" xml attribute names and ").append(attributeValues.size()).append(" xml attribute values. The trailing extra data will be ignored.");
            logger.warn(msg.toString());
        }

        Map<String, String> attrs = new LinkedHashMap();

        for(int i = 0; i < attributeNames.size(); ++i) {
            attrs.put((String)attributeNames.get(i), (String)attributeValues.get(i));
        }

        this.fields.put(fieldId, new FormField(fieldId, attrs));
    }

    void setFields(Map<String, FormField> newFieldsMap) {
        if (logger.isDebugEnabled()) {
            logger.debug("Setting new fields map " + newFieldsMap);
        }

        this.fields = newFieldsMap;
    }

    void addControlForField(String fieldId, String template, List<String> controlParamNames, List<String> controlParamValues) {
        if (controlParamNames == null) {
            controlParamNames = Collections.emptyList();
        }

        if (controlParamValues == null) {
            controlParamValues = Collections.emptyList();
        }

        if (controlParamNames.size() < controlParamValues.size() && logger.isWarnEnabled()) {
            StringBuilder msg = new StringBuilder();
            msg.append("field ").append(fieldId).append(" has ").append(controlParamNames.size()).append(" control-param names and ").append(controlParamValues.size()).append(" control-param values. The trailing extra data will be ignored.");
            logger.warn(msg.toString());
        }

        FormField field = (FormField)this.fields.get(fieldId);
        field.getControl().setTemplate(template);

        for(int i = 0; i < controlParamNames.size(); ++i) {
            ControlParam cp = new ControlParam((String)controlParamNames.get(i), (String)controlParamValues.get(i));
            field.getControl().addControlParam(cp);
        }

    }

    void addConstraintForField(String fieldId, String type, String message, String messageId, String validationHandler, String event) {
        FormField field = (FormField)this.fields.get(fieldId);
        field.addConstraintDefinition(type, message, messageId, validationHandler, event);
    }
}
