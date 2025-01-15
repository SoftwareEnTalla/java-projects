//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.header;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.ConfigException;

public class HeaderItem {
    private static final long serialVersionUID = -8543180919661884269L;
    private static final String ATTR_ID = "id";
    private static final String ATTR_TYPE = "type";
    private static final String ATTR_ICON = "icon";
    private static final String ATTR_LABEL = "label";
    private static final String ATTR_DESCRIPTION = "description";
    private static final String ATTR_PERMISSION = "permission";
    private static final String ATTR_CONDITION = "condition";
    private static Log logger = LogFactory.getLog(HeaderItem.class);
    private String generatedId;
    private String text;
    private final Map<String, String> attributes;
    private Map<String, HeaderItemsConfigElement> containers;

    public HeaderItem(String id, Map<String, String> attributes) {
        this(id, attributes, (String)null);
    }

    public HeaderItem(String generatedId, Map<String, String> attributes, String text) {
        this.containers = new LinkedHashMap();
        if (generatedId == null) {
            String msg = "Illegal null field id";
            if (logger.isWarnEnabled()) {
                logger.warn(msg);
            }

            throw new ConfigException(msg);
        } else {
            this.generatedId = generatedId;
            if (attributes == null) {
                attributes = Collections.emptyMap();
            }

            this.attributes = attributes;
            this.text = text;
        }
    }

    public String getGeneratedId() {
        return this.generatedId;
    }

    public String getId() {
        return (String)this.attributes.get("id");
    }

    public String getType() {
        return (String)this.attributes.get("type");
    }

    public String getIcon() {
        String icon = (String)this.attributes.get("icon");
        if (icon == null) {
            icon = this.getId().concat(".png");
            this.attributes.put("icon", icon);
        }

        return icon;
    }

    public String getLabel() {
        String label = (String)this.attributes.get("label");
        if (label == null) {
            label = "header.".concat(this.getId()).concat(".label");
            this.attributes.put("label", label);
        }

        return label;
    }

    public String getDescription() {
        String description = (String)this.attributes.get("description");
        if (description == null) {
            description = "header.".concat(this.getId()).concat(".description");
            this.attributes.put("description", description);
        }

        return description;
    }

    public String getPermission() {
        String permission = (String)this.attributes.get("permission");
        if (permission == null) {
            permission = "";
            this.attributes.put("permission", permission);
        }

        return permission;
    }

    public String getCondition() {
        String condition = (String)this.attributes.get("condition");
        if (condition == null) {
            condition = "";
            this.attributes.put("condition", condition);
        }

        return condition;
    }

    public String getValue() {
        return this.text == null ? "" : this.text;
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append("HeaderItem: ").append(this.generatedId);
        if (this.text != null) {
            result.append(" value:").append(this.text);
        }

        return result.toString();
    }

    public HeaderItemsConfigElement[] getContainers() {
        return (HeaderItemsConfigElement[])this.getContainersAsList().toArray(new HeaderItemsConfigElement[0]);
    }

    public List<HeaderItemsConfigElement> getContainersAsList() {
        List<HeaderItemsConfigElement> result = new ArrayList(this.containers.size());
        Iterator var2 = this.containers.entrySet().iterator();

        while(var2.hasNext()) {
            Map.Entry<String, HeaderItemsConfigElement> entry = (Map.Entry)var2.next();
            result.add((HeaderItemsConfigElement)entry.getValue());
        }

        return Collections.unmodifiableList(result);
    }

    void addContainedItem(String containerId, HeaderItemsConfigElement container) {
        this.containers.put(containerId, container);
    }
}
