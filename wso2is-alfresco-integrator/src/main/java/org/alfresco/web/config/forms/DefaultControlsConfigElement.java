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

public class DefaultControlsConfigElement extends ConfigElementAdapter {
    public static final String CONFIG_ELEMENT_ID = "default-controls";
    private static final long serialVersionUID = -6758804774427314050L;
    private final Map<String, Control> datatypeDefCtrlMappings = new LinkedHashMap();

    public DefaultControlsConfigElement() {
        super("default-controls");
    }

    public DefaultControlsConfigElement(String name) {
        super(name);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the default-controls config via the generic interfaces is not supported");
    }

    public ConfigElement combine(ConfigElement configElement) {
        if (configElement == null) {
            return this;
        } else {
            DefaultControlsConfigElement otherDCCElement = (DefaultControlsConfigElement)configElement;
            DefaultControlsConfigElement result = new DefaultControlsConfigElement();

            Iterator var4;
            String nextDataType;
            String nextTemplate;
            Control nextDefaultControls;
            List nextControlParams;
            for(var4 = this.datatypeDefCtrlMappings.keySet().iterator(); var4.hasNext(); result.addDataMapping(nextDataType, nextTemplate, nextControlParams)) {
                nextDataType = (String)var4.next();
                nextTemplate = this.getTemplateFor(nextDataType);
                nextDefaultControls = (Control)this.datatypeDefCtrlMappings.get(nextDataType);
                nextControlParams = null;
                if (nextDefaultControls != null) {
                    nextControlParams = nextDefaultControls.getParamsAsList();
                }
            }

            for(var4 = otherDCCElement.datatypeDefCtrlMappings.keySet().iterator(); var4.hasNext(); result.addDataMapping(nextDataType, nextTemplate, nextControlParams)) {
                nextDataType = (String)var4.next();
                nextTemplate = otherDCCElement.getTemplateFor(nextDataType);
                nextDefaultControls = (Control)otherDCCElement.datatypeDefCtrlMappings.get(nextDataType);
                nextControlParams = null;
                if (nextDefaultControls != null) {
                    nextControlParams = nextDefaultControls.getParamsAsList();
                }
            }

            return result;
        }
    }

    void addDataMapping(String dataType, String template, List<ControlParam> parameters) {
        if (parameters == null) {
            parameters = Collections.emptyList();
        }

        Control newControl = new Control(template);
        Iterator var5 = parameters.iterator();

        while(var5.hasNext()) {
            ControlParam p = (ControlParam)var5.next();
            newControl.addControlParam(p);
        }

        this.datatypeDefCtrlMappings.put(dataType, newControl);
    }

    public String[] getItemNames() {
        return (String[])this.getItemNamesAsList().toArray(new String[0]);
    }

    public List<String> getItemNamesAsList() {
        Set<String> result = this.datatypeDefCtrlMappings.keySet();
        List<String> resultList = new ArrayList(result);
        return Collections.unmodifiableList(resultList);
    }

    public Map<String, Control> getItems() {
        return Collections.unmodifiableMap(this.datatypeDefCtrlMappings);
    }

    public String getTemplateFor(String dataType) {
        Control ctrl = (Control)this.datatypeDefCtrlMappings.get(dataType);
        return ctrl == null ? null : ctrl.getTemplate();
    }

    public ControlParam[] getControlParamsFor(String dataType) {
        return (ControlParam[])this.getControlParamsAsListFor(dataType).toArray(new ControlParam[0]);
    }

    public List<ControlParam> getControlParamsAsListFor(String dataType) {
        return Collections.unmodifiableList(((Control)this.datatypeDefCtrlMappings.get(dataType)).getParamsAsList());
    }
}
