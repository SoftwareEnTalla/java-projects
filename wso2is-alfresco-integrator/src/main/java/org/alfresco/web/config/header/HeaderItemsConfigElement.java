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
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class HeaderItemsConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = 7464040585168773676L;
    private static Log logger = LogFactory.getLog(HeaderItemsConfigElement.class);
    private String id = "";
    private String label = "";
    private String permission = "";
    private String condition = "";
    public static final String DEFAULT_ELEMENT_ID = "app-items";
    private Map<String, HeaderItem> items = new LinkedHashMap();

    public HeaderItemsConfigElement() {
        super("app-items");
    }

    public HeaderItemsConfigElement(String name) {
        super(name);
    }

    public HeaderItem[] getItems() {
        return (HeaderItem[])this.getItemsAsList().toArray(new HeaderItem[0]);
    }

    public List<HeaderItem> getItemsAsList() {
        List<HeaderItem> result = new ArrayList(this.items.size());
        Iterator var2 = this.items.entrySet().iterator();

        while(var2.hasNext()) {
            Map.Entry<String, HeaderItem> entry = (Map.Entry)var2.next();
            result.add((HeaderItem)entry.getValue());
        }

        return Collections.unmodifiableList(result);
    }

    public HeaderItem getItem(String id) {
        return (HeaderItem)this.items.get(id);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the default-controls config via the generic interfaces is not supported");
    }

    public ConfigElement combine(ConfigElement configElement) {
        return (ConfigElement)(configElement == null ? this : configElement);
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public void setCondition(String condition) {
        this.condition = condition;
    }

    public String getId() {
        return this.id == null ? "" : this.id;
    }

    public String getLabel() {
        String label = this.label;
        if (label == null) {
            label = "header.".concat(this.getId()).concat(".label");
            this.label = label;
        }

        return label;
    }

    public String getPermission() {
        return this.permission == null ? "" : this.permission;
    }

    public String getCondition() {
        return this.condition == null ? "" : this.condition;
    }

    HeaderItem addItem(String id, List<String> attributeNames, List<String> attributeValues) {
        return this.addItem(id, attributeNames, attributeValues, (String)null);
    }

    HeaderItem addItem(String id, List<String> attributeNames, List<String> attributeValues, String itemText) {
        if (attributeNames == null) {
            attributeNames = Collections.emptyList();
        }

        if (attributeValues == null) {
            attributeValues = Collections.emptyList();
        }

        if (attributeNames.size() < attributeValues.size() && logger.isWarnEnabled()) {
            StringBuilder msg = new StringBuilder();
            msg.append("item ").append(id).append(" has ").append(attributeNames.size()).append(" xml attribute names and ").append(attributeValues.size()).append(" xml attribute values. The trailing extra data will be ignored.");
            logger.warn(msg.toString());
        }

        Map<String, String> attrs = new LinkedHashMap();

        for(int i = 0; i < attributeNames.size(); ++i) {
            attrs.put((String)attributeNames.get(i), (String)attributeValues.get(i));
        }

        HeaderItem hi = new HeaderItem(id, attrs, itemText);
        this.items.put(id, hi);
        return hi;
    }
}
