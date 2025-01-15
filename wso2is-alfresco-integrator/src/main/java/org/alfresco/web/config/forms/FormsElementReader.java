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

public class FormsElementReader implements ConfigElementReader {
    public static final String ATTR_NAME_ID = "id";
    public static final String ELEMENT_FORMS = "forms";

    public FormsElementReader() {
    }

    public ConfigElement parse(Element formsElement) {
        FormsConfigElement result = null;
        if (formsElement == null) {
            return null;
        } else {
            String name = formsElement.getName();
            if (!name.equals("forms")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse forms elements, the element passed was '" + name + "'");
            } else {
                result = new FormsConfigElement();
                Iterator var4 = formsElement.selectNodes("./form").iterator();

                Object obj;
                Element depsElement;
                while(var4.hasNext()) {
                    obj = var4.next();
                    depsElement = (Element)obj;
                    FormElementReader formReader = new FormElementReader();
                    FormConfigElement form = (FormConfigElement)formReader.parse(depsElement);
                    if (form.getId() == null) {
                        result.setDefaultForm(form);
                    } else {
                        result.addFormById(form, form.getId());
                    }
                }

                var4 = formsElement.selectNodes("./default-controls").iterator();

                while(var4.hasNext()) {
                    obj = var4.next();
                    depsElement = (Element)obj;
                    DefaultControlsElementReader defltCtrlsReader = new DefaultControlsElementReader();
                    DefaultControlsConfigElement defltCtrlsCE = (DefaultControlsConfigElement)defltCtrlsReader.parse(depsElement);
                    result.setDefaultControls(defltCtrlsCE);
                }

                var4 = formsElement.selectNodes("./constraint-handlers").iterator();

                while(var4.hasNext()) {
                    obj = var4.next();
                    depsElement = (Element)obj;
                    ConstraintHandlersElementReader constraintHandlersReader = new ConstraintHandlersElementReader();
                    ConstraintHandlersConfigElement constraintHandlersCE = (ConstraintHandlersConfigElement)constraintHandlersReader.parse(depsElement);
                    result.setConstraintHandlers(constraintHandlersCE);
                }

                var4 = formsElement.selectNodes("./dependencies").iterator();

                while(var4.hasNext()) {
                    obj = var4.next();
                    depsElement = (Element)obj;
                    DependenciesElementReader depsReader = new DependenciesElementReader();
                    DependenciesConfigElement depsCE = (DependenciesConfigElement)depsReader.parse(depsElement);
                    result.setDependencies(depsCE);
                }

                return result;
            }
        }
    }
}
