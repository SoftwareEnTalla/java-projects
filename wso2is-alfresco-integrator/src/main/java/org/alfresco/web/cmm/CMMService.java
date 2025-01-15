//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.cmm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.scripts.DictionaryQuery;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.extensions.surf.ModuleDeploymentService;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.ModelObjectPersisterException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.types.ExtensionModule;
import org.springframework.extensions.surf.types.ModuleDeployment;
import org.springframework.extensions.surf.uri.UriUtils;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Description;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.processor.FTLTemplateProcessor;

public abstract class CMMService extends DeclarativeWebScript {
    private static final Log logger = LogFactory.getLog(CMMService.class);
    private static final String JSON_APPEARANCE = "appearance";
    private static final String JSON_LABEL = "label";
    private static final String JSON_STYLECLASS = "styleclass";
    private static final String JSON_STYLE = "style";
    private static final String JSON_MAXLENGTH = "maxlength";
    private static final String JSON_READ_ONLY = "read-only";
    private static final String JSON_HIDDEN = "hidden";
    private static final String JSON_FORCE = "force";
    private static final String JSON_ANY = "any";
    private static final String JSON_FOR_MODE = "for-mode";
    private static final String JSON_CONTROLTYPE = "controltype";
    private static final String JSON_ELEMENTCONFIG = "elementconfig";
    private static final String JSON_ID = "id";
    private static final String JSON_COLUMN = "column";
    private static final String JSON_PSEUDONYM = "pseudonym";
    private static final String JSON_PROPERTIES = "properties";
    private static final String JSON_TITLE = "title";
    private static final String JSON_PREFIXEDNAME = "prefixedName";
    private static final String JSON_ENTRY = "entry";
    private static final String JSON_ACTIVE = "ACTIVE";
    private static final String JSON_STATUS = "status";
    private static final String JSON_ARGUMENTS = "arguments";
    private static final String JSON_DATA = "data";
    private static final String JSON_OPERATION = "operation";
    private static final String JSON_TYPES = "types";
    private static final String TEMPLATE_SET = "set";
    private static final String TEMPLATE_LABEL = "label";
    private static final String TEMPLATE_APPEARANCE = "appearance";
    private static final String TEMPLATE_PASSWORD = "password";
    private static final String TEMPLATE_STYLE = "style";
    private static final String TEMPLATE_STYLECLASS = "styleclass";
    private static final String TEMPLATE_MAXLENGTH = "maxLength";
    private static final String TEMPLATE_READONLY = "readonly";
    private static final String TEMPLATE_FORCE = "force";
    private static final String TEMPLATE_MODE = "mode";
    private static final String TEMPLATE_PARAMS = "params";
    private static final String TEMPLATE_ID = "id";
    private static final String TEMPLATE_FIELDS = "fields";
    private static final String TEMPLATE_SETS = "sets";
    private static final String TEMPLATE_PROPERTIES = "properties";
    private static final String TEMPLATE_TITLE = "title";
    private static final String TEMPLATE_FORM = "form";
    private static final String TEMPLATE_NAME = "name";
    private static final String TEMPLATE_ENTITIES = "entities";
    private static final String TEMPLATE_ASPECTS = "aspects";
    private static final String TEMPLATE_SUBTYPES = "subtypes";
    private static final String TEMPLATE_TYPES = "types";
    private static final String TEMPLATE_MODULE_NAME = "moduleName";
    private static final String TEMPLATE_TEMPLATE = "template";
    private static final String CONTROLTYPE_DEFAULT = "default";
    private static final String CONTROLTYPE_PASSWORD = "password";
    private static final String CONTROLTYPE_RICHTEXT = "richtext";
    private static final String CONTROLTYPE_TEXTAREA = "textarea";
    private static final String CONTROLTYPE_CONTENT = "content";
    private static final String CONTROLTYPE_TEXTFIELD = "textfield";
    private static final String CONTROLTYPE_HIDDEN = "hidden";
    private static final String CONTROLTYPE_SIZE = "size";
    private static final String CONTROLTYPE_MIMETYPE = "mimetype";
    private static final String CONTROLTYPE_TAGGABLE = "taggable";
    private static final String CONTROLTYPE_CATEGORIES = "categories";
    private static final String CM_FOLDER = "cm:folder";
    private static final String CM_CONTENT = "cm:content";
    private static final String MODULE_PREFIX = "CMM_";
    private static final String MODULE_TEMPLATE_PATH = "/org/alfresco/cmm/components/module-configuration.ftl";
    protected static final String DEFAULT_OK_RESULT = "{\"success\":true}";
    private static final String OP_DELETE_PROPERTY = "deleteProperty";
    private static final String OP_EDIT_PROPERTY = "editProperty";
    private static final String OP_CREATE_PROPERTY = "createProperty";
    private static final String OP_DELETE_PROPERTY_GROUP = "deletePropertyGroup";
    private static final String OP_EDIT_PROPERTY_GROUP = "editPropertyGroup";
    private static final String OP_CREATE_PROPERTY_GROUP = "createPropertyGroup";
    private static final String OP_DELETE_TYPE = "deleteType";
    private static final String OP_EDIT_TYPE = "editType";
    private static final String OP_CREATE_TYPE = "createType";
    private static final String OP_DELETE_MODEL = "deleteModel";
    private static final String OP_DEACTIVATE_MODEL = "deactivateModel";
    private static final String OP_ACTIVATE_MODEL = "activateModel";
    private static final String OP_EDIT_MODEL = "editModel";
    private static final String OP_CREATE_MODEL = "createModel";
    protected static Map<String, String> operationMapping = new HashMap<String, String>() {
        {
            this.put("createModel", "/-default-/private/alfresco/versions/1/cmm");
            this.put("editModel", "/-default-/private/alfresco/versions/1/cmm/{name}");
            this.put("activateModel", "/-default-/private/alfresco/versions/1/cmm/{name}?select=status");
            this.put("deactivateModel", "/-default-/private/alfresco/versions/1/cmm/{name}?select=status");
            this.put("deleteModel", "/-default-/private/alfresco/versions/1/cmm/{name}");
            this.put("createType", "/-default-/private/alfresco/versions/1/cmm/{name}/types");
            this.put("editType", "/-default-/private/alfresco/versions/1/cmm/{name}/types/{typeName}");
            this.put("deleteType", "/-default-/private/alfresco/versions/1/cmm/{name}/types/{typeName}");
            this.put("createPropertyGroup", "/-default-/private/alfresco/versions/1/cmm/{name}/aspects");
            this.put("editPropertyGroup", "/-default-/private/alfresco/versions/1/cmm/{name}/aspects/{aspectName}");
            this.put("deletePropertyGroup", "/-default-/private/alfresco/versions/1/cmm/{name}/aspects/{aspectName}");
            this.put("createProperty", "/-default-/private/alfresco/versions/1/cmm/{name}/{entityClass}/{entityName}?select=props");
            this.put("editProperty", "/-default-/private/alfresco/versions/1/cmm/{name}/{entityClass}/{entityName}?select=props&update={propertyName}");
            this.put("deleteProperty", "/-default-/private/alfresco/versions/1/cmm/{name}/{entityClass}/{entityName}?select=props&delete={propertyName}");
        }
    };
    protected ModuleDeploymentService moduleDeploymentService;
    protected DictionaryQuery dictionary;
    protected FTLTemplateProcessor templateProcessor;
    public static final Cache CACHE_NEVER = new Cache(new Description.RequiredCache() {
        public boolean getNeverCache() {
            return true;
        }

        public boolean getIsPublic() {
            return false;
        }

        public boolean getMustRevalidate() {
            return true;
        }
    });

    public CMMService() {
    }

    public void setModuleDeploymentService(ModuleDeploymentService moduleDeploymentService) {
        this.moduleDeploymentService = moduleDeploymentService;
    }

    public void setDictionary(DictionaryQuery dictionary) {
        this.dictionary = dictionary;
    }

    public void setTemplateProcessor(FTLTemplateProcessor templateProcessor) {
        this.templateProcessor = templateProcessor;
    }

    protected String serviceModelOperation(Status status, String modelName, JSONObject json) throws IOException {
        String opId = (String)json.get("operation");
        JSONObject data = (JSONObject)json.get("data");
        String url = (String)operationMapping.get(opId);
        if (url == null) {
            throw new IllegalArgumentException("Specified API operation does not map to a known URL: " + opId);
        } else {
            Map<String, String> args = new HashMap();
            JSONObject arguments = (JSONObject)json.get("arguments");
            if (arguments != null) {
                Iterator var9 = arguments.keySet().iterator();

                while(var9.hasNext()) {
                    String key = (String)var9.next();
                    args.put(key, URLEncoder.encode((String)arguments.get(key)));
                }
            }

            url = UriUtils.replaceUriTokens(url, args);
            if (logger.isDebugEnabled()) {
                logger.debug("Executing service operation: " + opId + " with URL: " + url + " method: " + this.getDescription().getMethod() + " - using data:\n" + (data != null ? data.toJSONString() : "null"));
            }

            Map<String, String> updatedForms = null;
            Response preResponse = null;
            JSONObject model;
            String oldPrefix;
            switch (opId) {
                case "deleteModel":
                case "deactivateModel":
                    model = this.getModel(modelName);
                    oldPrefix = (String)model.get("namespacePrefix");
                    Connector var10000 = this.getConnector();
                    String var10001 = URLEncoder.encode(oldPrefix);
                    preResponse = var10000.call("/api/dictionary?model=" + var10001 + ":" + URLEncoder.encode(modelName));
                    break;
                case "editModel":
                    model = this.getModel(modelName);
                    oldPrefix = (String)model.get("namespacePrefix");
                    String newPrefix = (String)data.get("namespacePrefix");
                    if (!newPrefix.equals(oldPrefix)) {
                        ExtensionModule module = this.getExtensionModule(modelName);
                        if (module != null) {
                            updatedForms = this.getFormDefinitions(module);
                            if (updatedForms.size() != 0) {
                                Iterator var17 = updatedForms.keySet().iterator();

                                while(var17.hasNext()) {
                                    String formId = (String)var17.next();
                                    String form = (String)updatedForms.get(formId);
                                    updatedForms.put(formId, form.replace("\"id\":\"" + oldPrefix + ":", "\"id\":\"" + newPrefix + ":"));
                                }
                            }
                        }
                    }
            }

            Response res;
            if (data != null) {
                res = this.getAPIConnector().call(url, new ConnectorContext(HttpMethod.valueOf(this.getDescription().getMethod())), new ByteArrayInputStream(data.toJSONString().getBytes("UTF-8")));
            } else {
                res = this.getAPIConnector().call(url, new ConnectorContext(HttpMethod.valueOf(this.getDescription().getMethod())));
            }

            if (logger.isDebugEnabled()) {
                Log var23 = logger;
                int var24 = res.getStatus().getCode();
                var23.debug("Response: " + var24 + "\n" + res.getResponse());
            }

            int statusCode = res.getStatus().getCode();
            if (statusCode >= 200 && statusCode < 300) {
                switch (opId) {
                    case "activateModel":
                        if (logger.isDebugEnabled()) {
                            logger.debug("ACTIVATE model config id: " + modelName);
                        }

                        this.updateDictionaryForModel(modelName);
                        this.buildExtensionModule(status, modelName, (FormOperation)null, true);
                        break;
                    case "deactivateModel":
                        if (logger.isDebugEnabled()) {
                            logger.debug("DEACTIVATE model config id: " + modelName);
                        }

                        if (preResponse != null && preResponse.getStatus().getCode() == 200) {
                            this.dictionary.updateRemoveClasses(preResponse.getResponse());
                        } else if (logger.isWarnEnabled()) {
                            logger.warn("Unable to update Share local Data Dictionary as Repository API call failed.");
                        }

                        this.buildExtensionModule(status, modelName, (FormOperation)null, false);
                    case "createModel":
                    case "deleteType":
                    case "deletePropertyGroup":
                    default:
                        break;
                    case "editModel":
                        if (updatedForms != null && updatedForms.size() != 0) {
                            this.buildExtensionModule(status, modelName, new FormOperation(CMMService.FormOperationEnum.Create, updatedForms), false);
                        }
                        break;
                    case "deleteModel":
                        if (logger.isDebugEnabled()) {
                            logger.debug("Deleting extension and form definitions for model: " + modelName);
                        }

                        this.deleteExtensionModule(status, modelName);
                        break;
                    case "createType":
                    case "editType":
                        if (this.isModelActive(this.getModel(modelName))) {
                            this.updateDictionaryForModel(modelName);
                            this.buildExtensionModule(status, modelName, (FormOperation)null, true);
                        }
                        break;
                    case "createPropertyGroup":
                    case "editPropertyGroup":
                        if (this.isModelActive(this.getModel(modelName))) {
                            this.buildExtensionModule(status, modelName, (FormOperation)null, true);
                            this.updateDictionaryForModel(modelName);
                        }
                        break;
                    case "createProperty":
                    case "deleteProperty":
                        if (this.isModelActive(this.getModel(modelName))) {
                            this.buildExtensionModule(status, modelName, (FormOperation)null, true);
                        }
                }
            }

            status.setCode(statusCode);
            return res.getResponse();
        }
    }

    private void updateDictionaryForModel(String modelName) {
        if (logger.isDebugEnabled()) {
            logger.debug("Updating dictionary for model: " + modelName);
        }

        JSONObject model = this.getModel(modelName);
        String prefix = (String)model.get("namespacePrefix");
        Connector var10000 = this.getConnector();
        String var10001 = URLEncoder.encode(prefix);
        Response res = var10000.call("/api/dictionary?model=" + var10001 + ":" + URLEncoder.encode(modelName));
        if (logger.isDebugEnabled()) {
            Log var5 = logger;
            int var6 = res.getStatus().getCode();
            var5.debug("Dictionary get response " + var6 + "\n" + res.getResponse());
        }

        if (res.getStatus().getCode() == 200) {
            this.dictionary.updateAddClasses(res.getResponse());
        }

    }

    protected JSONObject getModel(String modelName) {
        Response res = this.getAPIConnector().call("/-default-/private/alfresco/versions/1/cmm/" + URLEncoder.encode(modelName));
        if (res.getStatus().getCode() == 200) {
            return (JSONObject)this.getJsonBody(res).get("entry");
        } else {
            throw new AlfrescoRuntimeException("Unable to retrieve model information: " + modelName + " (" + res.getStatus().getCode() + ")");
        }
    }

    protected String buildModuleId(String modelName) {
        return "CMM_" + modelName;
    }

    private boolean isModelActive(JSONObject model) {
        return model.get("status").equals("ACTIVE");
    }

    protected void buildExtensionModule(Status status, String modelName, FormOperation formOp) {
        boolean active = this.isModelActive(this.getModel(modelName));
        this.buildExtensionModule(status, modelName, formOp, active);
    }

    protected void buildExtensionModule(Status status, String modelName, FormOperation formOp, JSONObject model) {
        boolean active = this.isModelActive(model);
        this.buildExtensionModule(status, modelName, formOp, active);
    }

    protected void buildExtensionModule(Status status, String modelName, FormOperation formOp, boolean active) {
        String moduleId = this.buildModuleId(modelName);
        TWrapper model = new TWrapper(8);
        model.put((String)"moduleName", moduleId);
        List<Object> typeList = new ArrayList();
        model.put((String)"types", typeList);
        List<Object> subtypesList = new ArrayList();
        model.put((String)"subtypes", subtypesList);
        List<Object> aspectsList = new ArrayList();
        model.put((String)"aspects", aspectsList);
        List<Object> entitiesList = new ArrayList();
        model.put((String)"entities", entitiesList);
        Map<String, String> formDefs = new HashMap();
        ExtensionModule module = this.getExtensionModule(modelName);
        if (module != null) {
            formDefs = this.getFormDefinitions(module);
        }

        if (formOp != null) {
            formOp.perform((Map)formDefs);
        }

        Iterator var13 = ((Map)formDefs).keySet().iterator();

        while(var13.hasNext()) {
            String entityId = (String)var13.next();
            TWrapper wrapper = new TWrapper(4);
            wrapper.put((String)"name", entityId).put("form", ((Map)formDefs).get(entityId));
            entitiesList.add(wrapper);
        }

        if (active) {
            Response response = this.getAPIConnector().call("/-default-/private/alfresco/versions/1/cmm/" + URLEncoder.encode(modelName) + "?select=all");
            if (response.getStatus().getCode() != 200) {
                throw new AlfrescoRuntimeException("Unable to retrieve types and aspects for model id: " + modelName);
            }

            JSONObject jsonData = this.getJsonBody(response);
            JSONArray types = (JSONArray)((JSONObject)jsonData.get("entry")).get("types");
            Map<String, List<TWrapper>> subtypeMap = new HashMap();
            Iterator var17 = types.iterator();

            label107:
            while(true) {
                String typeName=null;
                do {
                    JSONObject type=null;
                    TWrapper formWrappers=null;
                    do {
                        if (!var17.hasNext()) {
                            var17 = subtypeMap.keySet().iterator();

                            while(var17.hasNext()) {
                                String type1 = (String)var17.next();
                                TWrapper stypeWrapper = new TWrapper(4);
                                stypeWrapper.put((String)"name", type1).put("subtypes", subtypeMap.get(type1));
                                subtypesList.add(stypeWrapper);
                            }

                            JSONArray aspects = (JSONArray)((JSONObject)jsonData.get("entry")).get("aspects");
                            Iterator var35 = aspects.iterator();

                            while(var35.hasNext()) {
                                Object a = var35.next();
                                JSONObject aspect = (JSONObject)a;
                                String aspectName = (String)aspect.get("prefixedName");
                                formWrappers = this.processFormWidgets((Map)formDefs, aspect);
                                TWrapper aspectWrapper = new TWrapper(8);
                                aspectWrapper.put((String)"name", aspectName).put((String)"title", (String)aspect.get("title"));
                                aspectsList.add(aspectWrapper);
                                aspectWrapper.putAll(formWrappers);
                            }
                            break label107;
                        }

                        Object t = var17.next();
                        type = (JSONObject)t;
                        typeName = (String)type.get("prefixedName");
                        formWrappers = this.processFormWidgets((Map)formDefs, type);
                    } while(formWrappers.size() == 0);

                    formWrappers = new TWrapper(8);
                    formWrappers.put((String)"name", typeName).put((String)"title", (String)type.get("title"));
                    typeList.add(formWrappers);
                    formWrappers.putAll(formWrappers);
                } while(!this.dictionary.isSubType(typeName, "cm:content") && !this.dictionary.isSubType(typeName, "cm:folder"));

                String parentType = typeName;

                while(true) {
                    parentType = this.dictionary.getParent(parentType);
                    List<TWrapper> subtypes = (List)subtypeMap.get(parentType);
                    if (subtypes == null) {
                        subtypes = new ArrayList(4);
                        subtypeMap.put(parentType, subtypes);
                    }

                    boolean found = false;
                    Iterator var26 = ((List)subtypes).iterator();

                    while(var26.hasNext()) {
                        TWrapper st = (TWrapper)var26.next();
                        if (st.get("name").equals(typeName)) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        TWrapper subtypeWrapper = new TWrapper(4);
                        subtypeWrapper.put((String)"name", typeName).put((String)"title", this.dictionary.getTitle(typeName));
                        ((List)subtypes).add(subtypeWrapper);
                    }

                    if ("cm:content".equals(parentType) || "cm:folder".equals(parentType)) {
                        break;
                    }
                }
            }
        }

        Writer out = new StringBuilderWriter(4096);

        try {
            this.templateProcessor.process("/org/alfresco/cmm/components/module-configuration.ftl", model, out);
            if (logger.isDebugEnabled()) {
                logger.debug("Attempting to save module config:\r\n" + out.toString());
            }

            if (module == null) {
                this.moduleDeploymentService.addModuleToExtension(out.toString());
            } else {
                this.moduleDeploymentService.updateModuleToExtension(out.toString());
            }

            if (logger.isDebugEnabled()) {
                logger.debug("addModuleToExtension() completed.");
            }
        } catch (DocumentException | ModelObjectPersisterException | WebScriptException var28) {
            logger.error("Failed to execute template to construct module configuration.", var28);
            this.errorResponse(status, var28.getMessage());
        }

    }

    protected TWrapper processFormWidgets(Map<String, String> forms, JSONObject entity) {
        TWrapper formPropertyWrappers = new TWrapper(8);
        String entityName = (String)entity.get("name");
        String formDef = (String)forms.get(entityName);
        if (formDef != null) {
            try {
                Object o = (new JSONParser()).parse(formDef);
                if (o instanceof JSONArray) {
                    JSONArray formElements = (JSONArray)o;
                    if (formElements.size() != 0) {
                        List<TWrapper> properties = new ArrayList();
                        formPropertyWrappers.put((String)"properties", properties);
                        List<TWrapper> sets = new ArrayList();
                        formPropertyWrappers.put((String)"sets", sets);
                        List<TWrapper> fields = new ArrayList();
                        formPropertyWrappers.put((String)"fields", fields);
                        Map<String, TWrapper> fieldMap = new HashMap();
                        Iterator var12 = formElements.iterator();

                        while(true) {
                            if (!var12.hasNext()) {
                                fields.addAll(fieldMap.values());
                                break;
                            }

                            Object item = var12.next();
                            if (!(item instanceof JSONObject)) {
                                throw new IllegalStateException("Unexpected item in form structure: " + formDef);
                            }

                            int numCols = 0;
                            String columnSetTemplate = null;
                            switch ((String)((JSONObject)item).get("pseudonym")) {
                                case "cmm/editor/layout/1cols":
                                    numCols = 1;
                                    break;
                                case "cmm/editor/layout/2cols":
                                    numCols = 2;
                                    columnSetTemplate = "/org/alfresco/components/form/2-column-set.ftl";
                                    break;
                                case "cmm/editor/layout/2colswideleft":
                                    numCols = 2;
                                    columnSetTemplate = "/org/alfresco/components/form/2-column-wide-left-set.ftl";
                                    break;
                                case "cmm/editor/layout/3cols":
                                    numCols = 3;
                                    columnSetTemplate = "/org/alfresco/components/form/3-column-set.ftl";
                            }

                            if (numCols != 0) {
                                List<TWrapper> colProperties = new ArrayList();
                                JSONArray column = (JSONArray)((JSONObject)item).get("column");
                                String setId;
                                TWrapper fieldWrapper;
                                if (column != null) {
                                    Iterator var19 = column.iterator();

                                    while(var19.hasNext()) {
                                        Object w = var19.next();
                                        JSONObject widget = (JSONObject)w;
                                        setId = (String)widget.get("pseudonym");
                                        String id = (String)widget.get("id");
                                        if (logger.isDebugEnabled()) {
                                            logger.debug("Processing widget: " + id + " of type: " + setId);
                                        }

                                        TWrapper controlProperties = (new TWrapper(4)).put((String)"name", id);
                                        colProperties.add(controlProperties);
                                        JSONObject config = (JSONObject)widget.get("elementconfig");
                                        if (config != null) {
                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Found 'elementconfig' for widget - processing...");
                                            }

                                            Map<String, Object> controlParams = new HashMap(4);
                                            fieldWrapper = (new TWrapper(4)).put((String)"id", id).put((String)"params", controlParams);
                                            fieldMap.put(id, fieldWrapper);
                                            String controlType = (String)config.get("controltype");
                                            String mode = (String)config.get("for-mode");
                                            if (mode != null && !mode.equals("any")) {
                                                controlProperties.put((String)"mode", mode);
                                            }

                                            Boolean readOnly;
                                            if (config.get("force") instanceof Boolean) {
                                                readOnly = (Boolean)config.get("force");
                                                if (Boolean.TRUE == readOnly) {
                                                    controlProperties.put((String)"force", true);
                                                }
                                            }

                                            if (config.get("hidden") instanceof Boolean) {
                                                readOnly = (Boolean)config.get("hidden");
                                                if (Boolean.TRUE == readOnly) {
                                                    controlType = "hidden";
                                                }
                                            }

                                            if (config.get("read-only") instanceof Boolean) {
                                                readOnly = (Boolean)config.get("read-only");
                                                if (Boolean.TRUE == readOnly) {
                                                    fieldWrapper.put((String)"readonly", true);
                                                }
                                            }

                                            Number maxLength = (Number)config.get("maxlength");
                                            if (maxLength != null) {
                                                controlParams.put("maxLength", maxLength);
                                            }

                                            String style = (String)config.get("style");
                                            if (style != null && style.length() != 0) {
                                                controlParams.put("style", style);
                                            }

                                            String styleClass = (String)config.get("styleclass");
                                            if (styleClass != null && styleClass.length() != 0) {
                                                controlParams.put("styleclass", styleClass);
                                            }

                                            String template = null;
                                            if (controlType != null) {
                                                switch (controlType) {
                                                    case "textfield":
                                                        template = "/org/alfresco/components/form/controls/textfield.ftl";
                                                        break;
                                                    case "textarea":
                                                        template = "/org/alfresco/components/form/controls/textarea.ftl";
                                                        break;
                                                    case "content":
                                                        template = "/org/alfresco/components/form/controls/content.ftl";
                                                        break;
                                                    case "richtext":
                                                        template = "/org/alfresco/components/form/controls/richtext.ftl";
                                                        break;
                                                    case "password":
                                                        template = "/org/alfresco/components/form/controls/textfield.ftl";
                                                        controlParams.put("password", "true");
                                                        break;
                                                    case "hidden":
                                                        template = "/org/alfresco/components/form/controls/hidden.ftl";
                                                        break;
                                                    case "size":
                                                        template = "/org/alfresco/components/form/controls/size.ftl";
                                                        break;
                                                    case "mimetype":
                                                        template = "/org/alfresco/components/form/controls/mimetype.ftl";
                                                        break;
                                                    case "taggable":
                                                        controlParams.put("compactMode", "true");
                                                        controlParams.put("params", "aspect=cm:taggable");
                                                        controlParams.put("createNewItemUri", "/api/tag/workspace/SpacesStore");
                                                        controlParams.put("createNewItemIcon", "tag");
                                                        break;
                                                    case "categories":
                                                        controlParams.put("compactMode", "true");
                                                    case "default":
                                                        break;
                                                    default:
                                                        if (logger.isDebugEnabled()) {
                                                            logger.debug("WARNING: unknown control type for template mapping: " + controlType);
                                                        }
                                                }

                                                if (template != null) {
                                                    fieldWrapper.put((String)"template", template);
                                                    if (logger.isDebugEnabled()) {
                                                        logger.debug("Widget control template: " + template);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                JSONObject config = (JSONObject)((JSONObject)item).get("elementconfig");
                                String panelLabel = (String)config.get("label");
                                boolean hasLabel = panelLabel != null && panelLabel.length() != 0;
                                Object var10000 = entity.get("prefixedName");
                                setId = "" + var10000 + "_cmm_set" + sets.size();
                                TWrapper setWrapper = new TWrapper(8);
                                setWrapper.put("appearance", hasLabel ? config.get("appearance") : "whitespace").put((String)"id", setId);
                                if (numCols > 1) {
                                    setWrapper.put((String)"template", columnSetTemplate);
                                }

                                if (hasLabel) {
                                    setWrapper.put("label", config.get("label"));
                                }

                                sets.add(setWrapper);
                                Iterator var42 = colProperties.iterator();

                                while(var42.hasNext()) {
                                    TWrapper property = (TWrapper)var42.next();
                                    String id = (String)property.get("name");
                                    fieldWrapper = (TWrapper)fieldMap.get(id);
                                    if (fieldWrapper == null) {
                                        fieldWrapper = (new TWrapper(4)).put((String)"id", id);
                                        fieldMap.put(id, fieldWrapper);
                                    }

                                    fieldWrapper.put((String)"set", setId);
                                    if (logger.isDebugEnabled()) {
                                        logger.debug("Field mapping of: " + id + " mapped to set:" + setId);
                                    }
                                }

                                properties.addAll(colProperties);
                            }
                        }
                    }
                }
            } catch (ParseException var36) {
                logger.warn("Unable to parse Form definition for entity: " + entityName + "\n" + formDef + "\n" + var36.getMessage());
            }
        }

        return formPropertyWrappers;
    }

    protected void deleteExtensionModule(Status status, String modelName) {
        if (logger.isDebugEnabled()) {
            Log var10000 = logger;
            String var10001 = this.buildModuleId(modelName);
            var10000.debug("Attempting to delete module: " + var10001);
        }

        try {
            this.moduleDeploymentService.deleteModuleFromExtension(this.buildModuleId(modelName));
        } catch (ModelObjectPersisterException | DocumentException var4) {
            logger.error("Failed to execute template to construct module configuration.", var4);
            this.errorResponse(status, var4.getMessage());
        }

        if (logger.isDebugEnabled()) {
            logger.debug("deleteModuleFromExtension() completed.");
        }

    }

    protected ExtensionModule getExtensionModule(String modelName) {
        String moduleId = this.buildModuleId(modelName);
        ExtensionModule module = null;
        Iterator var4 = this.moduleDeploymentService.getDeployedModules().iterator();

        while(var4.hasNext()) {
            ModuleDeployment m = (ModuleDeployment)var4.next();
            if (moduleId.equals(m.getId())) {
                module = m.getExtensionModule();
                if (logger.isDebugEnabled()) {
                    logger.debug("Found existing module for ID: " + moduleId);
                }
            }
        }

        if (module == null && logger.isDebugEnabled()) {
            logger.debug("No module found for ID: " + moduleId);
        }

        return module;
    }

    protected Map<String, String> getFormDefinitions(String modelName) {
        return this.getFormDefinitions(this.getExtensionModule(modelName));
    }

    protected Map<String, String> getFormDefinitions(ExtensionModule module) {
        Map<String, String> forms = new HashMap();
        if (module != null) {
            List<Element> configs = module.getConfigurations();
            Iterator var4 = configs.iterator();

            while(var4.hasNext()) {
                Element config = (Element)var4.next();
                List<Element> nodeForms = new ArrayList();
                Iterator var7 = config.selectNodes("config/form-definition").iterator();

                while(var7.hasNext()) {
                    Object obj = var7.next();
                    nodeForms.add((Element)obj);
                }

                var7 = nodeForms.iterator();

                while(var7.hasNext()) {
                    Element form = (Element)var7.next();
                    String formId = form.attributeValue("id");
                    String formJSON = form.getText();
                    forms.put(formId, formJSON);
                }
            }
        }

        return forms;
    }

    protected Connector getConnector() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();

        try {
            return rc.getServiceRegistry().getConnectorService().getConnector("alfresco", rc.getUserId(), ServletUtil.getSession());
        } catch (ConnectorServiceException var3) {
            throw new AlfrescoRuntimeException("Connector exception.", var3);
        }
    }

    protected Connector getAPIConnector() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();

        try {
            return rc.getServiceRegistry().getConnectorService().getConnector("alfresco-api", rc.getUserId(), ServletUtil.getSession());
        } catch (ConnectorServiceException var3) {
            throw new AlfrescoRuntimeException("Connector exception.", var3);
        }
    }

    protected JSONObject getJsonBody(WebScriptRequest req) {
        try {
            JSONObject jsonData = null;
            String content = req.getContent().getContent();
            if (content != null && content.length() != 0) {
                Object o = (new JSONParser()).parse(content);
                if (o instanceof JSONObject) {
                    jsonData = (JSONObject)o;
                }
            }

            return jsonData;
        } catch (IOException | ParseException var5) {
            throw new AlfrescoRuntimeException("Failed to retrieve or parse JSON body.", var5);
        }
    }

    protected JSONObject getJsonBody(Response res) {
        try {
            JSONObject jsonData = null;
            String content = res.getResponse();
            if (content != null && content.length() != 0) {
                Object o = (new JSONParser()).parse(content);
                if (o instanceof JSONObject) {
                    jsonData = (JSONObject)o;
                }
            }

            return jsonData;
        } catch (ParseException var5) {
            throw new AlfrescoRuntimeException("Failed to retrieve or parse JSON body.", var5);
        }
    }

    protected void errorResponse(Status status, String msg) {
        status.setCode(500);
        status.setMessage(msg);
        status.setRedirect(true);
    }

    class FormOperation {
        private final FormOperationEnum op;
        private final String entityId;
        private final String form;
        private final Map<String, String> forms;

        FormOperation(FormOperationEnum op, String entityId, String form) {
            this.op = op;
            if (entityId != null && entityId.length() != 0) {
                this.entityId = entityId;
                this.form = form;
                this.forms = null;
            } else {
                throw new IllegalArgumentException("EntityID is mandatory.");
            }
        }

        FormOperation(FormOperationEnum op, Map<String, String> forms) {
            this.op = op;
            if (forms == null) {
                throw new IllegalArgumentException("Forms map is mandatory.");
            } else {
                this.entityId = null;
                this.form = null;
                this.forms = forms;
            }
        }

        void perform(Map<String, String> forms) {
            switch (this.op) {
                case Create:
                    forms.putAll(this.forms);
                    break;
                case Update:
                    forms.put(this.entityId, this.form);
                    break;
                case Delete:
                    forms.remove(this.entityId);
            }

        }
    }

    static enum FormOperationEnum {
        Create,
        Update,
        Delete;

        private FormOperationEnum() {
        }
    }

    public static class TWrapper extends HashMap<String, Object> implements Map<String, Object> {
        public TWrapper(int size) {
            super(size);
        }

        public TWrapper put(String key, Object value) {
            super.put(key, value);
            return this;
        }

        public TWrapper putAll(Object... args) {
            for(int i = 0; i < args.length; i += 2) {
                super.put((String)args[i], args[i + 1]);
            }

            return this;
        }
    }
}
