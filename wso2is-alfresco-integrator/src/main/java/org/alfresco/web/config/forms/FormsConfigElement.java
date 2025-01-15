//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class FormsConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = -7196705568492121773L;
    public static final String FORMS_ID = "forms";
    private FormConfigElement defaultFormElement;
    private Map<String, FormConfigElement> formElementsById = new LinkedHashMap();
    private DefaultControlsConfigElement defaultControlsElement;
    private ConstraintHandlersConfigElement constraintHandlersElement;
    private DependenciesConfigElement dependenciesConfigElement;

    public FormsConfigElement() {
        super("forms");
    }

    public FormsConfigElement(String name) {
        super(name);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the forms config via the generic interfaces is not supported");
    }

    public FormConfigElement getDefaultForm() {
        return this.defaultFormElement;
    }

    public FormConfigElement getForm(String id) {
        return (FormConfigElement)this.formElementsById.get(id);
    }

    void setDefaultForm(FormConfigElement formCE) {
        this.defaultFormElement = formCE;
    }

    void addFormById(FormConfigElement formCE, String formId) {
        this.formElementsById.put(formId, formCE);
    }

    public DefaultControlsConfigElement getDefaultControls() {
        return this.defaultControlsElement;
    }

    void setDefaultControls(DefaultControlsConfigElement defltCtrlsCE) {
        this.defaultControlsElement = defltCtrlsCE;
    }

    public ConstraintHandlersConfigElement getConstraintHandlers() {
        return this.constraintHandlersElement;
    }

    void setConstraintHandlers(ConstraintHandlersConfigElement constraintHandlersCE) {
        this.constraintHandlersElement = constraintHandlersCE;
    }

    public DependenciesConfigElement getDependencies() {
        return this.dependenciesConfigElement;
    }

    void setDependencies(DependenciesConfigElement dependenciesCS) {
        this.dependenciesConfigElement = dependenciesCS;
    }

    public ConfigElement combine(ConfigElement otherConfigElement) {
        FormsConfigElement otherFormsElem = (FormsConfigElement)otherConfigElement;
        FormsConfigElement result = new FormsConfigElement();
        Object combinedDefaultForm;
        if (this.getDefaultForm() == null) {
            combinedDefaultForm = otherFormsElem.getDefaultForm();
        } else {
            combinedDefaultForm = this.defaultFormElement.combine(otherFormsElem.getDefaultForm());
        }

        result.setDefaultForm((FormConfigElement)combinedDefaultForm);
        Iterator var5 = this.formElementsById.keySet().iterator();

        String otherFormId;
        while(var5.hasNext()) {
            otherFormId = (String)var5.next();
            if (otherFormsElem.formElementsById.containsKey(otherFormId)) {
                FormConfigElement otherFormCE = otherFormsElem.getForm(otherFormId);
                FormConfigElement combinedElement = (FormConfigElement)((FormConfigElement)this.formElementsById.get(otherFormId)).combine(otherFormCE);
                result.addFormById(combinedElement, otherFormId);
            } else {
                result.addFormById((FormConfigElement)this.formElementsById.get(otherFormId), otherFormId);
            }
        }

        var5 = otherFormsElem.formElementsById.keySet().iterator();

        while(var5.hasNext()) {
            otherFormId = (String)var5.next();
            if (!this.formElementsById.containsKey(otherFormId)) {
                result.addFormById((FormConfigElement)otherFormsElem.formElementsById.get(otherFormId), otherFormId);
            }
        }

        ConfigElement combinedDefaultControls = this.defaultControlsElement == null ? otherFormsElem.getDefaultControls() : this.defaultControlsElement.combine(otherFormsElem.getDefaultControls());
        result.setDefaultControls((DefaultControlsConfigElement)combinedDefaultControls);
        ConfigElement combinedConstraintHandlers = this.constraintHandlersElement == null ? otherFormsElem.getConstraintHandlers() : this.constraintHandlersElement.combine(otherFormsElem.getConstraintHandlers());
        result.setConstraintHandlers((ConstraintHandlersConfigElement)combinedConstraintHandlers);
        ConfigElement combinedDependencies = this.dependenciesConfigElement == null ? otherFormsElem.getDependencies() : this.dependenciesConfigElement.combine(otherFormsElem.getDependencies());
        result.setDependencies((DependenciesConfigElement)combinedDependencies);
        return result;
    }
}
