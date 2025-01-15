//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

class Dictionary {
    static final String JSON_IS_ASPECT = "isAspect";
    static final String JSON_IS_CONTAINER = "isContainer";
    static final String JSON_DESCRIPTION = "description";
    static final String JSON_TITLE = "title";
    static final String JSON_PROPERTIES = "properties";
    static final String JSON_DEFAULT_ASPECTS = "defaultAspects";
    static final String JSON_NAME = "name";
    static final String JSON_PARENT = "parent";
    static final String JSON_DATATYPE = "dataType";
    static final String JSON_DEFAULTVALUE = "defaultValue";
    static final String JSON_MULTIVALUED = "multiValued";
    static final String JSON_MANDATORY = "mandatory";
    static final String JSON_ENFORCED = "enforced";
    static final String JSON_PROTECTED = "protected";
    static final String JSON_INDEXED = "indexed";
    static final String JSON_ASSOCIATIONS = "associations";
    static final String JSON_CHILDASSOCIATIONS = "childassociations";
    static final String JSON_SOURCE = "source";
    static final String JSON_TARGET = "target";
    static final String JSON_CLASS = "class";
    static final String JSON_ROLE = "role";
    static final String JSON_MANY = "many";
    private Map<String, DictionaryItem> types;
    private Map<String, DictionaryItem> aspects;

    Dictionary(Map<String, DictionaryItem> types, Map<String, DictionaryItem> aspects) {
        this.types = types;
        this.aspects = aspects;
    }

    public DictionaryItem getType(String type) {
        return (DictionaryItem)this.types.get(type);
    }

    public DictionaryItem getAspect(String aspect) {
        return (DictionaryItem)this.aspects.get(aspect);
    }

    public DictionaryItem getTypeOrAspect(String ddclass) {
        DictionaryItem item = (DictionaryItem)this.types.get(ddclass);
        if (item == null) {
            item = (DictionaryItem)this.aspects.get(ddclass);
        }

        return item;
    }

    public boolean isSubType(String type, String isType) {
        boolean isSubType = false;

        try {
            DictionaryItem ddtype = this.getType(type);

            while(!isSubType && ddtype != null) {
                JSONObject parent = ddtype.data.getJSONObject("parent");
                if (parent.has("name")) {
                    String parentName = parent.getString("name");
                    ddtype = (DictionaryItem)this.types.get(parentName);
                    if (ddtype != null) {
                        isSubType = isType.equals(ddtype.data.getString("name"));
                    }
                } else {
                    ddtype = null;
                }
            }

            return isSubType;
        } catch (JSONException var7) {
            throw new AlfrescoRuntimeException("Error retrieving 'isSubType' information for: " + type, var7);
        }
    }

    public String[] getSubTypes(String ddclass) {
        try {
            List<String> subTypes = new ArrayList();
            DictionaryItem dditem = this.getType(ddclass);
            Iterator var4;
            String aspectName;
            DictionaryItem ddAspect;
            String parentAspect;
            JSONObject parent;
            if (dditem != null) {
                var4 = this.types.keySet().iterator();

                while(var4.hasNext()) {
                    aspectName = (String)var4.next();
                    ddAspect = this.getType(aspectName);
                    parentAspect = null;

                    while(ddAspect != null) {
                        parent = ddAspect.data.getJSONObject("parent");
                        parentAspect = parent.optString("name");
                        if (parentAspect != null) {
                            if (parentAspect.equals(ddclass)) {
                                subTypes.add(parentAspect);
                                ddAspect = null;
                            } else {
                                ddAspect = this.getType(parentAspect);
                            }
                        }
                    }
                }
            } else {
                dditem = this.getAspect(ddclass);
                if (dditem != null) {
                    var4 = this.aspects.keySet().iterator();

                    while(var4.hasNext()) {
                        aspectName = (String)var4.next();
                        ddAspect = this.getAspect(aspectName);
                        parentAspect = null;

                        while(ddAspect != null) {
                            parent = ddAspect.data.getJSONObject("parent");
                            parentAspect = parent.optString("name");
                            if (parentAspect != null) {
                                if (parentAspect.equals(ddclass)) {
                                    subTypes.add(parentAspect);
                                    ddAspect = null;
                                } else {
                                    ddAspect = this.getAspect(parentAspect);
                                }
                            }
                        }
                    }
                }
            }

            return (String[])subTypes.toArray(new String[subTypes.size()]);
        } catch (JSONException var9) {
            throw new AlfrescoRuntimeException("Error retrieving 'subtype' information for: " + ddclass, var9);
        }
    }

    public String[] getAllTypes() {
        return (String[])this.types.keySet().toArray(new String[this.types.keySet().size()]);
    }

    public String[] getAllAspects() {
        return (String[])this.aspects.keySet().toArray(new String[this.aspects.keySet().size()]);
    }

    public boolean hasDefaultAspect(String type, String aspect) {
        boolean hasAspect = false;

        try {
            DictionaryItem ddtype = this.getType(type);
            if (ddtype != null) {
                JSONObject aspects = ddtype.data.getJSONObject("defaultAspects");

                for(Iterator<String> keys = aspects.keys(); !hasAspect && keys.hasNext(); hasAspect = aspect.equals(keys.next())) {
                }
            }

            return hasAspect;
        } catch (JSONException var7) {
            throw new AlfrescoRuntimeException("Error retrieving 'defaultAspects' information for: " + type, var7);
        }
    }

    public String[] getDefaultAspects(String type) {
        String[] defaultAspects = null;

        try {
            DictionaryItem ddtype = this.getType(type);
            if (ddtype != null) {
                JSONObject aspects = ddtype.data.getJSONObject("defaultAspects");
                defaultAspects = new String[aspects.length()];
                int count = 0;

                for(Iterator<String> keys = aspects.keys(); keys.hasNext(); defaultAspects[count++] = (String)keys.next()) {
                }
            }
        } catch (JSONException var7) {
            throw new AlfrescoRuntimeException("Error retrieving 'defaultAspects' information for: " + type, var7);
        }

        return defaultAspects != null ? defaultAspects : new String[0];
    }

    public boolean hasProperty(String ddclass, String property, boolean checkDefaultAspects) {
        boolean hasProperty = false;

        try {
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject properties = dditem.data.getJSONObject("properties");

                Iterator props;
                for(props = properties.keys(); !hasProperty && props.hasNext(); hasProperty = property.equals(props.next())) {
                }

                if (checkDefaultAspects && !hasProperty) {
                    JSONObject aspects = dditem.data.getJSONObject("defaultAspects");
                    Iterator<String> keys = aspects.keys();

                    while(true) {
                        DictionaryItem aspect;
                        do {
                            if (hasProperty || !keys.hasNext()) {
                                return hasProperty;
                            }

                            aspect = this.getAspect((String)keys.next());
                        } while(aspect == null);

                        for(props = aspect.data.getJSONObject("properties").keys(); !hasProperty && props.hasNext(); hasProperty = property.equals(props.next())) {
                        }
                    }
                }
            }

            return hasProperty;
        } catch (JSONException var11) {
            throw new AlfrescoRuntimeException("Error retrieving 'properties' information for: " + ddclass, var11);
        }
    }

    public String getTitle(String ddclass) {
        try {
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            return dditem != null ? dditem.data.getString("title") : null;
        } catch (JSONException var3) {
            throw new AlfrescoRuntimeException("Error retrieving 'title' information for: " + ddclass, var3);
        }
    }

    public String getDescription(String ddclass) {
        try {
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            return dditem != null ? dditem.data.getString("description") : null;
        } catch (JSONException var3) {
            throw new AlfrescoRuntimeException("Error retrieving 'description' information for: " + ddclass, var3);
        }
    }

    public String getParent(String ddclass) {
        try {
            String parentType = null;
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject parent = dditem.data.getJSONObject("parent");
                parentType = parent.optString("name");
            }

            return parentType;
        } catch (JSONException var5) {
            throw new AlfrescoRuntimeException("Error retrieving 'parent' information for: " + ddclass, var5);
        }
    }

    public boolean isContainer(String type) {
        try {
            DictionaryItem ddtype = this.getType(type);
            return ddtype != null ? ddtype.data.getBoolean("isContainer") : false;
        } catch (JSONException var3) {
            throw new AlfrescoRuntimeException("Error retrieving 'isContainer' information for: " + type, var3);
        }
    }

    public DictionaryProperty getProperty(String ddclass, String property, boolean checkDefaultAspects) {
        try {
            DictionaryProperty ddprop = null;
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject properties = dditem.data.getJSONObject("properties");
                if (properties.has(property)) {
                    ddprop = new DictionaryProperty(property, properties.getJSONObject(property));
                } else if (checkDefaultAspects) {
                    JSONObject aspects = dditem.data.getJSONObject("defaultAspects");
                    Iterator<String> keys = aspects.keys();

                    while(ddprop == null && keys.hasNext()) {
                        DictionaryItem aspect = this.getAspect((String)keys.next());
                        if (aspect != null) {
                            properties = aspect.data.getJSONObject("properties");
                            if (properties.has(property)) {
                                ddprop = new DictionaryProperty(property, properties.getJSONObject(property));
                            }
                        }
                    }
                }
            }

            return ddprop;
        } catch (JSONException var10) {
            throw new AlfrescoRuntimeException("Error retrieving 'properties' information for: " + ddclass, var10);
        }
    }

    public DictionaryProperty[] getProperties(String ddclass, boolean checkDefaultAspects) {
        try {
            DictionaryProperty[] ddprops = null;
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject properties = dditem.data.getJSONObject("properties");
                List<DictionaryProperty> propList = new ArrayList(properties.length());
                Iterator<String> props = properties.keys();

                while(props.hasNext()) {
                    String propName = (String)props.next();
                    propList.add(new DictionaryProperty(propName, properties.getJSONObject(propName)));
                }

                if (checkDefaultAspects) {
                    JSONObject aspects = dditem.data.getJSONObject("defaultAspects");
                    Iterator<String> keys = aspects.keys();

                    label40:
                    while(true) {
                        DictionaryItem aspect;
                        do {
                            if (!keys.hasNext()) {
                                break label40;
                            }

                            aspect = this.getAspect((String)keys.next());
                        } while(aspect == null);

                        properties = aspect.data.getJSONObject("properties");
                        props = properties.keys();

                        while(props.hasNext()) {
                            String propName = (String)props.next();
                            propList.add(new DictionaryProperty(propName, properties.getJSONObject(propName)));
                        }
                    }
                }

                ddprops = new DictionaryProperty[propList.size()];
                propList.toArray(ddprops);
            }

            return ddprops != null ? ddprops : new DictionaryProperty[0];
        } catch (JSONException var12) {
            throw new AlfrescoRuntimeException("Error retrieving 'properties' information for: " + ddclass, var12);
        }
    }

    public DictionaryAssoc[] getAssociations(String ddclass) {
        try {
            DictionaryAssoc[] ddassocs = null;
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject assocs = dditem.data.getJSONObject("associations");
                ddassocs = new DictionaryAssoc[assocs.length()];
                int count = 0;

                String assocName;
                for(Iterator<String> assocNames = assocs.keys(); assocNames.hasNext(); ddassocs[count++] = new DictionaryAssoc(assocName, assocs.getJSONObject(assocName))) {
                    assocName = (String)assocNames.next();
                }
            }

            return ddassocs != null ? ddassocs : new DictionaryAssoc[0];
        } catch (JSONException var8) {
            throw new AlfrescoRuntimeException("Error retrieving 'associations' information for: " + ddclass, var8);
        }
    }

    public DictionaryAssoc[] getChildAssociations(String ddclass) {
        try {
            DictionaryAssoc[] ddassocs = null;
            DictionaryItem dditem = this.getTypeOrAspect(ddclass);
            if (dditem != null) {
                JSONObject assocs = dditem.data.getJSONObject("childassociations");
                ddassocs = new DictionaryAssoc[assocs.length()];
                int count = 0;

                String assocName;
                for(Iterator<String> assocNames = assocs.keys(); assocNames.hasNext(); ddassocs[count++] = new DictionaryAssoc(assocName, assocs.getJSONObject(assocName))) {
                    assocName = (String)assocNames.next();
                }
            }

            return ddassocs != null ? ddassocs : new DictionaryAssoc[0];
        } catch (JSONException var8) {
            throw new AlfrescoRuntimeException("Error retrieving 'childassociations' information for: " + ddclass, var8);
        }
    }

    public void updateAddClasses(String classes) {
        try {
            JSONArray json = new JSONArray(classes);
            Map<String, DictionaryItem> types = (Map)((HashMap)this.types).clone();
            Map<String, DictionaryItem> aspects = (Map)((HashMap)this.aspects).clone();

            for(int i = 0; i < json.length(); ++i) {
                JSONObject ddclass = json.getJSONObject(i);
                String typeName = ddclass.getString("name");
                if (ddclass.getBoolean("isAspect")) {
                    aspects.put(typeName, new DictionaryItem(typeName, ddclass));
                } else {
                    types.put(typeName, new DictionaryItem(typeName, ddclass));
                }
            }

            this.types = types;
            this.aspects = aspects;
        } catch (JSONException var8) {
            throw new AlfrescoRuntimeException(var8.getMessage(), var8);
        }
    }

    public void updateRemoveClasses(String classes) {
        try {
            JSONArray json = new JSONArray(classes);
            Map<String, DictionaryItem> types = (Map)((HashMap)this.types).clone();
            Map<String, DictionaryItem> aspects = (Map)((HashMap)this.aspects).clone();

            for(int i = 0; i < json.length(); ++i) {
                JSONObject ddclass = json.getJSONObject(i);
                String typeName = ddclass.getString("name");
                if (ddclass.getBoolean("isAspect")) {
                    aspects.remove(typeName);
                } else {
                    types.remove(typeName);
                }
            }

            this.types = types;
            this.aspects = aspects;
        } catch (JSONException var8) {
            throw new AlfrescoRuntimeException(var8.getMessage(), var8);
        }
    }

    public String toString() {
        int var10000 = this.types.size();
        return "Dictionary contains " + var10000 + " types and " + this.aspects.size() + " aspects.";
    }

    public static class DictionaryItem {
        private final String type;
        private final JSONObject data;

        DictionaryItem(String type, JSONObject data) {
            this.type = type;
            this.data = data;
        }

        public int hashCode() {
            return this.type.hashCode();
        }

        public boolean equals(Object obj) {
            return this.type.equals(obj);
        }

        public String toString() {
            String var10000 = this.type.toString();
            return var10000 + "\r\n" + this.data.toString();
        }
    }

    public static class DictionaryProperty extends DictionaryMetaBase {
        DictionaryProperty(String name, JSONObject property) {
            super(name, property);
        }

        public String getTitle() {
            return this.getStringValue("title");
        }

        public String getDescription() {
            return this.getStringValue("description");
        }

        public String getDataType() {
            return this.getStringValue("dataType");
        }

        public String getDefaultValue() {
            return this.getStringValue("defaultValue");
        }

        public boolean getIsMultiValued() {
            return this.getBooleanValue("multiValued");
        }

        public boolean getIsMandatory() {
            return this.getBooleanValue("mandatory");
        }

        public boolean getIsEnforced() {
            return this.getBooleanValue("enforced");
        }

        public boolean getIsProtected() {
            return this.getBooleanValue("protected");
        }

        public boolean getIsIndexed() {
            return this.getBooleanValue("indexed");
        }
    }

    public static class DictionaryAssoc extends DictionaryMetaBase {
        DictionaryAssoc(String name, JSONObject assoc) {
            super(name, assoc);
        }

        public String getTitle() {
            return this.getStringValue("title");
        }

        public String getSourceClass() {
            return this.getStringValue("source", "class");
        }

        public String getSourceRole() {
            return this.getStringValue("source", "role");
        }

        public boolean getSourceIsMandatory() {
            return this.getBooleanValue("source", "mandatory");
        }

        public boolean getSourceIsMany() {
            return this.getBooleanValue("source", "many");
        }

        public String getTargetClass() {
            return this.getStringValue("target", "class");
        }

        public String getTargetRole() {
            return this.getStringValue("target", "role");
        }

        public boolean getTargetIsMandatory() {
            return this.getBooleanValue("target", "mandatory");
        }

        public boolean getTargetIsMany() {
            return this.getBooleanValue("target", "many");
        }
    }

    private abstract static class DictionaryMetaBase {
        private final JSONObject meta;
        private final String name;

        DictionaryMetaBase(String name, JSONObject meta) {
            this.name = name;
            this.meta = meta;
        }

        public String getName() {
            return this.name;
        }

        protected String getStringValue(String value) {
            try {
                return this.meta.getString(value);
            } catch (JSONException var3) {
                throw new AlfrescoRuntimeException("Error retrieving '" + value + "' information for item: " + this.name, var3);
            }
        }

        protected String getStringValue(String object, String value) {
            try {
                String result = null;
                if (this.meta.has(object)) {
                    result = this.meta.getJSONObject(object).optString(value);
                }

                return result;
            } catch (JSONException var4) {
                throw new AlfrescoRuntimeException("Error retrieving '" + value + "' information for item: " + this.name, var4);
            }
        }

        protected boolean getBooleanValue(String value) {
            try {
                return this.meta.getBoolean(value);
            } catch (JSONException var3) {
                throw new AlfrescoRuntimeException("Error retrieving '" + value + "' information for item: " + this.name, var3);
            }
        }

        protected boolean getBooleanValue(String object, String value) {
            try {
                boolean result = false;
                if (this.meta.has(object)) {
                    result = this.meta.getJSONObject(object).getBoolean(value);
                }

                return result;
            } catch (JSONException var4) {
                throw new AlfrescoRuntimeException("Error retrieving '" + value + "' information for item: " + this.name, var4);
            }
        }

        public String toString() {
            return this.name;
        }
    }
}
