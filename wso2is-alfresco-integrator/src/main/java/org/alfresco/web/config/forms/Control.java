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

public class Control {
    private String template;
    private final Map<String, ControlParam> controlParams;

    public Control() {
        this((String)null);
    }

    public Control(String template) {
        this.controlParams = new LinkedHashMap();
        this.template = template;
    }

    void addControlParam(String cpName, String cpValue) {
        ControlParam cp = new ControlParam(cpName, cpValue);
        this.addControlParam(cp);
    }

    void addControlParam(ControlParam param) {
        this.controlParams.put(param.getName(), param);
    }

    public String getTemplate() {
        return this.template;
    }

    void setTemplate(String newTemplate) {
        this.template = newTemplate;
    }

    public ControlParam[] getParams() {
        return (ControlParam[])this.getParamsAsList().toArray(new ControlParam[0]);
    }

    public List<ControlParam> getParamsAsList() {
        List<ControlParam> result = new ArrayList(this.controlParams.size());
        Iterator var2 = this.controlParams.entrySet().iterator();

        while(var2.hasNext()) {
            Map.Entry<String, ControlParam> entry = (Map.Entry)var2.next();
            result.add((ControlParam)entry.getValue());
        }

        return Collections.unmodifiableList(result);
    }

    public Control combine(Control otherControl) {
        String combinedTemplate = otherControl.template == null ? this.template : otherControl.template;
        Control result = new Control(combinedTemplate);
        Iterator var4 = this.controlParams.entrySet().iterator();

        Map.Entry otherEntry;
        ControlParam otherCP;
        while(var4.hasNext()) {
            otherEntry = (Map.Entry)var4.next();
            otherCP = (ControlParam)otherEntry.getValue();
            result.controlParams.put(otherCP.getName(), otherCP);
        }

        var4 = otherControl.controlParams.entrySet().iterator();

        while(var4.hasNext()) {
            otherEntry = (Map.Entry)var4.next();
            otherCP = (ControlParam)otherEntry.getValue();
            result.controlParams.put(otherCP.getName(), otherCP);
        }

        return result;
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(this.template);
        result.append(this.controlParams);
        return result.toString();
    }
}
