//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FormSet {
    private final String setId;
    private final String parentId;
    private final String appearance;
    private final String label;
    private final String labelId;
    private final String template;
    private FormSet parent;
    private List<FormSet> children;

    public FormSet(String setId) {
        this(setId, (String)null, (String)null, (String)null, (String)null, (String)null);
    }

    public FormSet(String setId, String parentId, String appearance, String label, String labelId) {
        this(setId, parentId, appearance, label, labelId, (String)null);
    }

    public FormSet(String setId, String parentId, String appearance, String label, String labelId, String template) {
        this.children = new ArrayList();
        this.setId = setId;
        this.parentId = parentId;
        this.appearance = appearance;
        this.label = label;
        this.labelId = labelId;
        this.template = template;
    }

    public String getSetId() {
        return this.setId;
    }

    public String getParentId() {
        return this.parentId;
    }

    public String getAppearance() {
        return this.appearance;
    }

    public String getLabel() {
        return this.label;
    }

    public String getLabelId() {
        return this.labelId;
    }

    public String getTemplate() {
        return this.template;
    }

    public FormSet getParent() {
        return this.parent;
    }

    public FormSet[] getChildren() {
        return (FormSet[])this.getChildrenAsList().toArray(new FormSet[0]);
    }

    public List<FormSet> getChildrenAsList() {
        return Collections.unmodifiableList(this.children);
    }

    void setParent(FormSet parentObject) {
        this.parent = parentObject;
    }

    void addChild(FormSet newChild) {
        this.children.add(newChild);
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append("Set: id='").append(this.setId).append("' parentId='").append(this.parentId).append("' appearance='").append(this.appearance).append("' label='").append(this.label).append("' labelId='").append(this.labelId).append("' template='").append(this.template).append("'");
        return result.toString();
    }
}
