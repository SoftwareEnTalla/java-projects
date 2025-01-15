//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.header;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.dom4j.Attribute;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

class HeaderItemsElementReader implements ConfigElementReader {
    public static final String ATTR_ID = "id";
    public static final String ATTR_LABEL = "label";
    public static final String ATTR_PERMISSION = "permission";
    public static final String ATTR_CONDITION = "condition";
    public static final String ELEMENT_APP_ITEMS = "app-items";
    public static final String ELEMENT_USER_ITEMS = "user-items";
    public static final String ELEMENT_CONTAINER_GROUP = "container-group";
    public static final String ELEMENT_LEGACY = "legacy-mode-enabled";
    public static final String ELEMENT_MAX_RECENT_SITES = "max-recent-sites";
    public static final String ELEMENT_MAX_DISPLAYED_SITE_PAGES = "max-displayed-site-pages";
    public static final String ID_SEPARATOR = "_";
    private String id_prefix = "";
    private String group_condition = null;
    private String group_permission = null;

    public HeaderItemsElementReader() {
    }

    public HeaderItemsElementReader(String id) {
        this.id_prefix = id != null && id.length() != 0 ? id.concat("_") : "";
    }

    public ConfigElement parse(Element headerItemsElement) {
        HeaderItemsConfigElement result = null;
        if (headerItemsElement == null) {
            return null;
        } else {
            String name = headerItemsElement.getName();
            if (!name.equals("app-items") && !name.equals("user-items") && !name.equals("container-group") && !name.equals("legacy-mode-enabled")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse app-items, user-items, container-group, legacy-mode-enabled elements, the element passed was '" + name + "'");
            } else {
                result = new HeaderItemsConfigElement(name);
                this.parseId(headerItemsElement, result);
                this.parseLabel(headerItemsElement, result);
                this.parseCondition(headerItemsElement, result);
                this.parsePermission(headerItemsElement, result);
                this.parseItemTags(headerItemsElement, result);
                return result;
            }
        }
    }

    private void parseItemTags(Element itemsElement, HeaderItemsConfigElement result) {
        Iterator var4 = itemsElement.selectNodes("./item").iterator();

        while(var4.hasNext()) {
            Object itemObj = var4.next();
            Element itemElem = (Element)itemObj;
            String itemText = itemElem.getTextTrim();
            List<Attribute> itemAttributes = new ArrayList();
            Iterator var9 = itemElem.selectNodes("./@*").iterator();

            while(var9.hasNext()) {
                Object obj = var9.next();
                itemAttributes.add((Attribute)obj);
            }

            List<String> itemAttributeNames = new ArrayList();
            List<String> itemAttributeValues = new ArrayList();
            String itemGeneratedId = null;
            String itemGroupCondition = this.group_condition;
            String itemGroupPermission = this.group_permission;
            Iterator var14 = itemAttributes.iterator();

            while(var14.hasNext()) {
                Attribute nextAttr = (Attribute)var14.next();
                String nextAttributeName = nextAttr.getName();
                String nextAttributeValue = nextAttr.getValue();
                if (nextAttributeName.equals("condition")) {
                    itemGroupCondition = null;
                } else if (nextAttributeName.equals("permission")) {
                    itemGroupPermission = null;
                } else if (nextAttributeName.equals("id")) {
                    itemGeneratedId = this.generateUniqueItemId(nextAttributeValue);
                }

                itemAttributeNames.add(nextAttributeName);
                itemAttributeValues.add(nextAttributeValue);
            }

            if (itemGeneratedId == null) {
                throw new ConfigException("<item> node missing mandatory id attribute.");
            }

            if (itemGroupCondition != null) {
                itemAttributeNames.add("condition");
                itemAttributeValues.add(itemGroupCondition);
            }

            if (itemGroupPermission != null) {
                itemAttributeNames.add("permission");
                itemAttributeValues.add(itemGroupPermission);
            }

            HeaderItem lastItem = result.addItem(itemGeneratedId, itemAttributeNames, itemAttributeValues, itemText);
            var14 = itemElem.selectNodes("./container-group").iterator();

            while(var14.hasNext()) {
                Object obj = var14.next();
                Element containerElement = (Element)obj;
                HeaderItemsElementReader containerReader = new HeaderItemsElementReader(lastItem.getId());
                HeaderItemsConfigElement containerCE = (HeaderItemsConfigElement)containerReader.parse(containerElement);
                lastItem.addContainedItem(containerCE.getId(), containerCE);
            }
        }

    }

    private void parseId(Element itemsElement, HeaderItemsConfigElement result) {
        String id = itemsElement.attributeValue("id");
        if (id == null && this.id_prefix.length() > 0) {
            throw new ConfigException(itemsElement.getName() + " node missing mandatory id attribute.");
        } else {
            result.setId(id);
            StringBuilder sb = new StringBuilder(this.id_prefix);
            if (id != null) {
                sb.append(id).append("_");
            }

            this.id_prefix = sb.toString();
        }
    }

    private void parseLabel(Element itemsElement, HeaderItemsConfigElement result) {
        String label = itemsElement.attributeValue("label");
        result.setLabel(label);
    }

    private void parseCondition(Element itemsElement, HeaderItemsConfigElement result) {
        String condition = itemsElement.attributeValue("condition");
        this.group_condition = condition;
        result.setCondition(condition);
    }

    private void parsePermission(Element itemsElement, HeaderItemsConfigElement result) {
        String permission = itemsElement.attributeValue("permission");
        this.group_permission = permission;
        result.setPermission(permission);
    }

    private String generateUniqueItemId(String id) {
        return id == null ? null : this.id_prefix.concat(id);
    }
}
