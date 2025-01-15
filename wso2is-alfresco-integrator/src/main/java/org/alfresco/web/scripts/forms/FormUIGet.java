//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts.forms;

import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.web.config.forms.ConstraintHandlerDefinition;
import org.alfresco.web.config.forms.ConstraintHandlersConfigElement;
import org.alfresco.web.config.forms.Control;
import org.alfresco.web.config.forms.ControlParam;
import org.alfresco.web.config.forms.DefaultControlsConfigElement;
import org.alfresco.web.config.forms.FormConfigElement;
import org.alfresco.web.config.forms.FormField;
import org.alfresco.web.config.forms.FormSet;
import org.alfresco.web.config.forms.FormsConfigElement;
import org.alfresco.web.config.forms.Mode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.extensions.config.Config;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.I18NUtil;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.webscripts.AbstractMessageHelper;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.ConfigModel;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.json.JSONWriter;
import org.springframework.util.StringUtils;

public class FormUIGet extends DeclarativeWebScript {
    private static Log logger = LogFactory.getLog(FormUIGet.class);
    protected static final String PROPERTY = "property";
    protected static final String ASSOCIATION = "association";
    protected static final String PROP_PREFIX = "prop:";
    protected static final String FIELD = "field";
    protected static final String SET = "set";
    protected static final String ASSOC_PREFIX = "assoc:";
    protected static final String OLD_DATA_TYPE_PREFIX = "d:";
    protected static final String ENDPOINT_ID = "alfresco";
    protected static final String ALFRESCO_PROXY = "/proxy/alfresco";
    protected static final String CM_NAME_PROP = "prop_cm_name";
    protected static final String MSG_DEFAULT_SET_LABEL = "form.default.set.label";
    protected static final String MSG_DEFAULT_FORM_ERROR = "form.error";
    protected static final String INDENT = "   ";
    protected static final String DELIMITER = "#alf#";
    protected static final String SUBMIT_TYPE_MULTIPART = "multipart";
    protected static final String SUBMIT_TYPE_JSON = "json";
    protected static final String SUBMIT_TYPE_URL = "urlencoded";
    protected static final String ENCTYPE_MULTIPART = "multipart/form-data";
    protected static final String ENCTYPE_JSON = "application/json";
    protected static final String ENCTYPE_URL = "application/x-www-form-urlencoded";
    protected static final String DEFAULT_MODE = "edit";
    protected static final String DEFAULT_SUBMIT_TYPE = "multipart";
    protected static final String DEFAULT_METHOD = "post";
    protected static final String DEFAULT_FIELD_TYPE = "text";
    protected static final String DEFAULT_CONSTRAINT_EVENT = "blur";
    protected static final String CONFIG_FORMS = "forms";
    protected static final String PARAM_ITEM_KIND = "itemKind";
    protected static final String PARAM_ITEM_ID = "itemId";
    protected static final String PARAM_FORM_ID = "formId";
    protected static final String PARAM_SUBMIT_TYPE = "submitType";
    protected static final String PARAM_SUBMISSION_URL = "submissionUrl";
    protected static final String PARAM_JS = "js";
    protected static final String PARAM_ERROR_KEY = "err";
    protected static final String CONSTRAINT_MANDATORY = "MANDATORY";
    protected static final String CONSTRAINT_LIST = "LIST";
    protected static final String CONSTRAINT_LENGTH = "LENGTH";
    protected static final String CONSTRAINT_NUMBER = "NUMBER";
    protected static final String CONSTRAINT_MINMAX = "MINMAX";
    protected static final String CONSTRAINT_REGEX = "REGEX";
    protected static final String CONSTRAINT_NODE_HANDLER = "Alfresco.forms.validation.nodeName";
    protected static final String CONSTRAINT_FILE_NAME_HANDLER = "Alfresco.forms.validation.fileName";
    protected static final String CONSTRAINT_MSG_LENGTH = "form.field.constraint.length";
    protected static final String CONSTRAINT_MSG_MINMAX = "form.field.constraint.minmax";
    protected static final String CONSTRAINT_MSG_NUMBER = "form.field.constraint.number";
    protected static final String CONTROL_SELECT_MANY = "/org/alfresco/components/form/controls/selectmany.ftl";
    protected static final String CONTROL_SELECT_ONE = "/org/alfresco/components/form/controls/selectone.ftl";
    protected static final String CONTROL_PARAM_OPTIONS = "options";
    protected static final String CONTROL_PARAM_OPTION_SEPARATOR = "optionSeparator";
    protected static final String MODEL_DATA = "data";
    protected static final String MODEL_DEFINITION = "definition";
    protected static final String MODEL_FIELDS = "fields";
    protected static final String MODEL_FORM_DATA = "formData";
    protected static final String MODEL_FORCE = "force";
    protected static final String MODEL_MESSAGE = "message";
    protected static final String MODEL_PROTECTED_FIELD = "protectedField";
    protected static final String MODEL_REPEATING = "repeating";
    protected static final String MODEL_DEFAULT_VALUE = "defaultValue";
    protected static final String MODEL_FORM = "form";
    protected static final String MODEL_ERROR = "error";
    protected static final String MODEL_NAME = "name";
    protected static final String MODEL_MODE = "mode";
    protected static final String MODEL_METHOD = "method";
    protected static final String MODEL_ENCTYPE = "enctype";
    protected static final String MODEL_SUBMISSION_URL = "submissionUrl";
    protected static final String MODEL_SHOW_CANCEL_BUTTON = "showCancelButton";
    protected static final String MODEL_SHOW_RESET_BUTTON = "showResetButton";
    protected static final String MODEL_SHOW_SUBMIT_BUTTON = "showSubmitButton";
    protected static final String MODEL_SHOW_CAPTION = "showCaption";
    protected static final String MODEL_DESTINATION = "destination";
    protected static final String MODEL_REDIRECT = "redirect";
    protected static final String MODEL_ARGUMENTS = "arguments";
    protected static final String MODEL_STRUCTURE = "structure";
    protected static final String MODEL_CONSTRAINTS = "constraints";
    protected static final String MODEL_VIEW_TEMPLATE = "viewTemplate";
    protected static final String MODEL_EDIT_TEMPLATE = "editTemplate";
    protected static final String MODEL_CREATE_TEMPLATE = "createTemplate";
    protected static final String MODEL_TYPE = "type";
    protected static final String MODEL_LABEL = "label";
    protected static final String MODEL_DESCRIPTION = "description";
    protected static final String MODEL_MANDATORY = "mandatory";
    protected static final String MODEL_DATA_TYPE = "dataType";
    protected static final String MODEL_DATA_TYPE_PARAMETERS = "dataTypeParameters";
    protected static final String MODEL_DATA_KEY_NAME = "dataKeyName";
    protected static final String MODEL_ENDPOINT_TYPE = "endpointType";
    protected static final String MODEL_ENDPOINT_MANDATORY = "endpointMandatory";
    protected static final String MODEL_ENDPOINT_MANY = "endpointMany";
    protected static final String MODEL_ENDPOINT_DIRECTION = "endpointDirection";
    protected static final String MODEL_JAVASCRIPT = "javascript";
    protected static final String MODEL_CAPABILITIES = "capabilities";
    protected static final String MODEL_PARAMETERS = "parameters";
    protected static final String MODEL_MAX_LENGTH = "maxLength";
    protected static final String MODEL_GROUP = "group";
    protected static final String MODEL_INDEX_TOKENISATION_MODE = "indexTokenisationMode";
    private static final String TYPE_INT = "int";
    private static final String TYPE_LONG = "long";
    private static final String TYPE_DOUBLE = "double";
    private static final String TYPE_FLOAT = "float";
    protected ConfigService configService;
    private MessageHelper messageHelper = null;

    public FormUIGet() {
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

    protected Map<String, Object> executeImpl(WebScriptRequest req, Status status, Cache cache) {
        Map<String, Object> model = null;
        String itemKind = this.getParameter(req, "itemKind");
        String itemId = this.getParameter(req, "itemId");
        if (logger.isDebugEnabled()) {
            logger.debug("itemKind = " + itemKind);
            logger.debug("itemId = " + itemId);
        }

        if (itemKind != null && itemId != null && itemKind.length() > 0 && itemId.length() > 0) {
            model = this.generateModel(itemKind, itemId, req, status, cache);
        } else {
            model = new HashMap(1);
            ((Map)model).put("form", (Object)null);
        }

        return (Map)model;
    }

    protected Map<String, Object> generateModel(String itemKind, String itemId, WebScriptRequest request, Status status, Cache cache) {
        Map<String, Object> model = null;
        String modeParam = this.getParameter(request, "mode", "edit");
        String formId = this.getParameter(request, "formId");
        Mode mode = Mode.modeFromString(modeParam);
        if (logger.isDebugEnabled()) {
            logger.debug("Showing " + mode + " form (id=" + formId + ") for item: [" + itemKind + "]" + itemId);
        }

        FormConfigElement formConfig = this.getFormConfig(itemId, formId);
        List<String> visibleFields = this.getVisibleFields(mode, formConfig);
        Response formSvcResponse = this.retrieveFormDefinition(itemKind, itemId, visibleFields, formConfig);
        if (formSvcResponse.getStatus().getCode() == 200) {
            model = this.generateFormModel(request, mode, formSvcResponse, formConfig);
        } else if (formSvcResponse.getStatus().getCode() == 401) {
            status.setCode(401);
            status.setRedirect(true);
        } else {
            String errorKey = this.getParameter(request, "err");
            model = this.generateErrorModel(formSvcResponse, errorKey);
        }

        return model;
    }

    protected String getParameter(WebScriptRequest req, String name) {
        return this.getParameter(req, name, (String)null);
    }

    protected String getParameter(WebScriptRequest req, String name, String defaultValue) {
        String value = req.getParameter(name);
        if ((value == null || value.length() == 0) && defaultValue != null) {
            value = defaultValue;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Returning \"" + value + "\" from getParameter for \"" + name + "\"");
        }

        return value;
    }

    protected FormConfigElement getFormConfig(String itemId, String formId) {
        FormConfigElement formConfig = null;
        FormsConfigElement formsConfig = null;
        RequestContext requestContext = ThreadLocalRequestContext.getRequestContext();
        ConfigModel extendedTemplateConfigModel = requestContext.getExtendedTemplateConfigModel((String)null);
        if (extendedTemplateConfigModel != null) {
            Map<String, ConfigElement> configs = (Map)extendedTemplateConfigModel.getScoped().get(itemId);
            formsConfig = (FormsConfigElement)configs.get("forms");
        }

        if (formsConfig == null) {
            Config configResult = this.configService.getConfig(itemId);
            formsConfig = (FormsConfigElement)configResult.getConfigElement("forms");
        }

        if (formsConfig != null) {
            if (formsConfig != null) {
                if (formId != null && formId.length() > 0) {
                    formConfig = formsConfig.getForm(formId);
                }

                if (formConfig == null) {
                    formConfig = formsConfig.getDefaultForm();
                }
            }
        } else if (logger.isWarnEnabled()) {
            logger.warn("Could not lookup form configuration as configService has not been set");
        }

        return formConfig;
    }

    protected List<String> getVisibleFields(Mode mode, FormConfigElement formConfig) {
        List<String> visibleFields = null;
        if (formConfig != null) {
            switch (mode) {
                case VIEW:
                    visibleFields = formConfig.getVisibleViewFieldNamesAsList();
                    break;
                case EDIT:
                    visibleFields = formConfig.getVisibleEditFieldNamesAsList();
                    break;
                case CREATE:
                    visibleFields = formConfig.getVisibleCreateFieldNamesAsList();
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Fields configured to be visible for " + mode + " mode = " + visibleFields);
        }

        return visibleFields;
    }

    protected List<String> getVisibleFieldsInSet(ModelContext context, FormSet setConfig) {
        List<String> visibleFields = null;
        Mode mode = context.getMode();
        if (setConfig != null) {
            switch (mode) {
                case VIEW:
                    visibleFields = context.getFormConfig().getVisibleViewFieldNamesForSetAsList(setConfig.getSetId());
                    break;
                case EDIT:
                    visibleFields = context.getFormConfig().getVisibleEditFieldNamesForSetAsList(setConfig.getSetId());
                    break;
                case CREATE:
                    visibleFields = context.getFormConfig().getVisibleCreateFieldNamesForSetAsList(setConfig.getSetId());
            }

            if (logger.isDebugEnabled()) {
                Log var10000 = logger;
                String var10001 = setConfig.getSetId();
                var10000.debug("Fields configured to be visible for set \"" + var10001 + "\" = " + visibleFields);
            }
        }

        return visibleFields;
    }

    protected Response retrieveFormDefinition(String itemKind, String itemId, List<String> visibleFields, FormConfigElement formConfig) {
        Response response = null;

        try {
            ConnectorService connService = FrameworkUtil.getConnectorService();
            RequestContext requestContext = ThreadLocalRequestContext.getRequestContext();
            String currentUserId = requestContext.getUserId();
            HttpSession currentSession = ServletUtil.getSession(true);
            Connector connector = connService.getConnector("alfresco", currentUserId, currentSession);
            ConnectorContext context = new ConnectorContext(HttpMethod.POST, (Map)null, buildDefaultHeaders());
            context.setContentType("application/json");
            response = connector.call("/api/formdefinitions", context, this.generateFormDefPostBody(itemKind, itemId, visibleFields, formConfig));
            if (logger.isDebugEnabled()) {
                logger.debug("Response status: " + response.getStatus().getCode());
            }
        } catch (Exception var12) {
            if (logger.isErrorEnabled()) {
                logger.error("Failed to get form definition: ", var12);
            }
        }

        return response;
    }

    private static Map<String, String> buildDefaultHeaders() {
        Map<String, String> headers = new HashMap(1, 1.0F);
        headers.put("Accept-Language", I18NUtil.getLocale().toString().replace('_', '-'));
        return headers;
    }

    protected String retrieveMessage(String messageKey, Object... args) {
        if (this.messageHelper == null) {
            this.messageHelper = new MessageHelper(this);
        }

        return this.messageHelper.get(messageKey, args);
    }

    protected ByteArrayInputStream generateFormDefPostBody(String itemKind, String itemId, List<String> visibleFields, FormConfigElement formConfig) throws IOException {
        StringBuilderWriter buf = new StringBuilderWriter(512);
        JSONWriter writer = new JSONWriter(buf);
        writer.startObject();
        writer.writeValue("itemKind", itemKind);
        writer.writeValue("itemId", itemId.replace(":/", ""));
        List<String> forcedFields = null;
        Iterator var8;
        String fieldId;
        if (visibleFields != null && visibleFields.size() > 0) {
            writer.startValue("fields");
            writer.startArray();
            forcedFields = new ArrayList(visibleFields.size());
            var8 = visibleFields.iterator();

            while(var8.hasNext()) {
                fieldId = (String)var8.next();
                writer.writeValue(fieldId);
                if (formConfig.isFieldForced(fieldId)) {
                    forcedFields.add(fieldId);
                }
            }

            writer.endArray();
        }

        if (forcedFields != null && forcedFields.size() > 0) {
            writer.startValue("force");
            writer.startArray();
            var8 = forcedFields.iterator();

            while(var8.hasNext()) {
                fieldId = (String)var8.next();
                writer.writeValue(fieldId);
            }

            writer.endArray();
        }

        writer.endObject();
        if (logger.isDebugEnabled()) {
            logger.debug("Generated JSON POST body: " + buf.toString());
        }

        return new ByteArrayInputStream(buf.toString().getBytes());
    }

    protected Map<String, Object> generateFormModel(WebScriptRequest request, Mode mode, Response formSvcResponse, FormConfigElement formConfig) {
        try {
            String jsonResponse = formSvcResponse.getResponse();
            if (logger.isDebugEnabled()) {
                logger.debug("form definition JSON = \n" + jsonResponse);
            }

            JSONObject formDefinition = new JSONObject(new JSONTokener(jsonResponse));
            Map<String, Object> model = new HashMap(1);
            model.put("form", this.generateFormUIModel(new ModelContext(request, mode, formDefinition, formConfig)));
            return model;
        } catch (JSONException var8) {
            if (logger.isErrorEnabled()) {
                logger.error(var8);
            }

            return null;
        }
    }

    protected Map<String, Object> generateFormUIModel(ModelContext context) {
        Map<String, Object> formUIModel = new HashMap(8);
        context.setFormUIModel(formUIModel);
        formUIModel.put("mode", context.getMode().toString());
        formUIModel.put("method", this.getParameter(context.getRequest(), "method", "post"));
        formUIModel.put("enctype", this.discoverEncodingFormat(context));
        formUIModel.put("submissionUrl", this.discoverSubmissionUrl(context));
        formUIModel.put("arguments", this.discoverArguments(context));
        formUIModel.put("data", this.discoverData(context));
        formUIModel.put("showCancelButton", this.discoverBooleanParam(context, "showCancelButton"));
        formUIModel.put("showResetButton", this.discoverBooleanParam(context, "showResetButton"));
        formUIModel.put("showSubmitButton", this.discoverBooleanParam(context, "showSubmitButton", true));
        String destination = this.getParameter(context.getRequest(), "destination");
        if (destination != null && destination.length() > 0) {
            formUIModel.put("destination", destination);
        }

        String redirect = this.getParameter(context.getRequest(), "redirect");
        if (redirect != null && redirect.length() > 0) {
            formUIModel.put("redirect", redirect);
        }

        this.processCapabilities(context, formUIModel);
        this.processTemplates(context, formUIModel);
        this.processFields(context, formUIModel);
        formUIModel.put("showCaption", this.discoverBooleanParam(context, "showCaption", this.getDefaultShowCaption(context)));
        this.dumpFormUIModel(formUIModel);
        return formUIModel;
    }

    private boolean getDefaultShowCaption(ModelContext context) {
        if (context.getMode() == Mode.VIEW) {
            return false;
        } else {
            Iterator var2 = context.getConstraints().iterator();

            Constraint constraint;
            do {
                if (!var2.hasNext()) {
                    return false;
                }

                constraint = (Constraint)var2.next();
            } while(!"MANDATORY".equals(constraint.getId()));

            return true;
        }
    }

    protected String discoverEncodingFormat(ModelContext context) {
        String submitType = this.getParameter(context.getRequest(), "submitType", "multipart");
        String enctype = null;
        if ("multipart".equals(submitType)) {
            enctype = "multipart/form-data";
        } else if ("json".equals(submitType)) {
            enctype = "application/json";
        } else if ("urlencoded".equals(submitType)) {
            enctype = "application/x-www-form-urlencoded";
        } else {
            enctype = "multipart/form-data";
        }

        return enctype;
    }

    protected String discoverSubmissionUrl(ModelContext context) {
        String submissionUrl = null;
        if (context.getFormConfig() != null && context.getFormConfig().getSubmissionURL() != null) {
            submissionUrl = context.getFormConfig().getSubmissionURL();
        } else {
            String defaultSubmissionUrl = null;

            try {
                JSONObject data = context.getFormDefinition().getJSONObject("data");
                defaultSubmissionUrl = data.getString("submissionUrl");
            } catch (JSONException var5) {
                throw new WebScriptException("Failed to find default submission URL", var5);
            }

            submissionUrl = this.getParameter(context.getRequest(), "submissionUrl", defaultSubmissionUrl);
        }

        String var10000 = this.getProxyPath(context);
        submissionUrl = var10000 + submissionUrl;
        return submissionUrl;
    }

    protected String getProxyPath(ModelContext context) {
        return context.getRequest().getContextPath() + "/proxy/alfresco";
    }

    protected Map<String, String> discoverArguments(ModelContext context) {
        Map<String, String> arguments = new HashMap(3);
        arguments.put("itemKind", this.getParameter(context.getRequest(), "itemKind"));
        arguments.put("itemId", this.getParameter(context.getRequest(), "itemId"));
        arguments.put("formId", this.getParameter(context.getRequest(), "formId"));
        return arguments;
    }

    protected Map<String, Object> discoverData(ModelContext context) {
        Map<String, Object> dataModel = null;

        try {
            JSONObject data = context.getFormDefinition().getJSONObject("data");
            JSONObject formData = data.getJSONObject("formData");
            JSONArray names = formData.names();
            if (names != null) {
                dataModel = new HashMap(names.length());

                for(int x = 0; x < names.length(); ++x) {
                    String key = names.getString(x);
                    ((Map)dataModel).put(key, formData.get(key));
                }
            } else {
                dataModel = Collections.emptyMap();
            }

            return (Map)dataModel;
        } catch (JSONException var8) {
            throw new WebScriptException("Failed to find form data", var8);
        }
    }

    protected boolean discoverBooleanParam(ModelContext context, String name) {
        return this.discoverBooleanParam(context, name, false);
    }

    protected boolean discoverBooleanParam(ModelContext context, String name, boolean defaultValue) {
        String value = this.getParameter(context.getRequest(), name, Boolean.toString(defaultValue));
        return "true".equals(value);
    }

    protected JSONObject discoverFieldDefinition(ModelContext context, String fieldName) {
        JSONObject fieldDefinition = null;
        JSONObject propertyDefinition = (JSONObject)context.getPropertyDefinitions().get(fieldName);
        JSONObject associationDefinition = (JSONObject)context.getAssociationDefinitions().get(fieldName);
        if (propertyDefinition == null && associationDefinition == null) {
            if (fieldName.indexOf("prop:") != -1) {
                propertyDefinition = (JSONObject)context.getPropertyDefinitions().get(fieldName.substring("prop:".length()));
            } else if (fieldName.indexOf("assoc:") != -1) {
                associationDefinition = (JSONObject)context.getAssociationDefinitions().get(fieldName.substring("assoc:".length()));
            }
        }

        if (propertyDefinition != null) {
            fieldDefinition = propertyDefinition;
        } else if (associationDefinition != null) {
            fieldDefinition = associationDefinition;
        }

        return fieldDefinition;
    }

    protected String discoverSetLabel(FormSet setConfig) {
        String label = null;
        if (setConfig.getLabelId() != null) {
            label = this.retrieveMessage(setConfig.getLabelId());
        } else if (setConfig.getLabel() != null) {
            label = setConfig.getLabel();
        } else if ("".equals(setConfig.getSetId())) {
            label = this.retrieveMessage("form.default.set.label");
        } else {
            label = setConfig.getSetId();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Returning label for set: " + label);
        }

        return label;
    }

    protected Map<String, List<String>> discoverSetMembership(ModelContext context) {
        Map<String, List<String>> setMemberships = new HashMap(4);

        try {
            JSONObject data = context.getFormDefinition().getJSONObject("data");
            JSONObject definition = data.getJSONObject("definition");
            JSONArray fieldsFromServer = definition.getJSONArray("fields");

            for(int x = 0; x < fieldsFromServer.length(); ++x) {
                JSONObject fieldDefinition = fieldsFromServer.getJSONObject(x);
                String fieldName = fieldDefinition.getString("name");
                if (!context.getFormConfig().isFieldHidden(fieldName, context.getMode())) {
                    String set = "";
                    if (fieldDefinition.has("group")) {
                        set = fieldDefinition.getString("group");
                    }

                    FormField fieldConfig = (FormField)context.getFormConfig().getFields().get(fieldName);
                    if (fieldConfig != null && !fieldConfig.getSet().equals("")) {
                        set = fieldConfig.getSet();
                    }

                    List<String> fieldsForSet = (List)setMemberships.get(set);
                    if (fieldsForSet == null) {
                        fieldsForSet = new ArrayList(4);
                        fieldsForSet.add(fieldName);
                        setMemberships.put(set, fieldsForSet);
                    } else {
                        fieldsForSet.add(fieldName);
                    }
                } else if (logger.isDebugEnabled()) {
                    logger.debug("Ignoring \"" + fieldName + "\" as it is configured to be hidden");
                }
            }
        } catch (JSONException var12) {
            if (logger.isErrorEnabled()) {
                logger.error("Failed to discover set membership", var12);
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Set membership = " + setMemberships);
        }

        return setMemberships;
    }

    protected void processCapabilities(ModelContext context, Map<String, Object> formUIModel) {
        String jsEnabled = this.getParameter(context.getRequest(), "js");
        if (jsEnabled != null && ("off".equalsIgnoreCase(jsEnabled) || "false".equalsIgnoreCase(jsEnabled) || "disabled".equalsIgnoreCase(jsEnabled))) {
            Map<String, Object> capabilities = new HashMap(1);
            capabilities.put("javascript", false);
            formUIModel.put("capabilities", capabilities);
            if (logger.isDebugEnabled()) {
                logger.debug("JavaScript disabled flag detected, added form capabilties: " + capabilities);
            }
        }

    }

    protected void processTemplates(ModelContext context, Map<String, Object> formUIModel) {
        FormConfigElement formConfig = context.getFormConfig();
        if (formConfig != null && formConfig.getViewTemplate() != null) {
            formUIModel.put("viewTemplate", formConfig.getViewTemplate());
            if (logger.isDebugEnabled()) {
                logger.debug("Set viewTemplate to \"" + formConfig.getViewTemplate() + "\"");
            }
        }

        if (formConfig != null && formConfig.getEditTemplate() != null) {
            formUIModel.put("editTemplate", formConfig.getEditTemplate());
            if (logger.isDebugEnabled()) {
                logger.debug("Set editTemplate to \"" + formConfig.getEditTemplate() + "\"");
            }
        }

        if (formConfig != null && formConfig.getCreateTemplate() != null) {
            formUIModel.put("createTemplate", formConfig.getCreateTemplate());
            if (logger.isDebugEnabled()) {
                logger.debug("Set createTemplate to \"" + formConfig.getCreateTemplate() + "\"");
            }
        }

    }

    protected void processFields(ModelContext context, Map<String, Object> formUIModel) {
        List<String> visibleFields = this.getVisibleFields(context.getMode(), context.getFormConfig());
        if (context.getFormConfig() != null && visibleFields != null && visibleFields.size() > 0) {
            this.processVisibleFields(context);
        } else {
            this.processServerFields(context);
        }

        formUIModel.put("fields", context.getFields());
        formUIModel.put("structure", context.getStructure());
        formUIModel.put("constraints", context.getConstraints());
    }

    protected void processVisibleFields(ModelContext context) {
        Iterator var2 = context.getFormConfig().getRootSetsAsList().iterator();

        while(var2.hasNext()) {
            FormSet setConfig = (FormSet)var2.next();
            Set set = this.generateSetModelUsingVisibleFields(context, setConfig);
            if (set != null) {
                context.getStructure().add(set);
            }
        }

    }

    protected void processServerFields(ModelContext context) {
        if (context.getFormConfig() != null) {
            Map<String, List<String>> setMembership = this.discoverSetMembership(context);
            Iterator var3 = context.getFormConfig().getRootSetsAsList().iterator();

            while(var3.hasNext()) {
                FormSet setConfig = (FormSet)var3.next();
                Set set = this.generateSetModelUsingServerFields(context, setConfig, setMembership);
                if (set != null) {
                    context.getStructure().add(set);
                }
            }
        } else {
            Set set = this.generateDefaultSetModelUsingServerFields(context);
            context.getStructure().add(set);
        }

    }

    protected Set generateSetModelUsingVisibleFields(ModelContext context, FormSet setConfig) {
        Set set = null;
        List<String> fieldsInSet = this.getVisibleFieldsInSet(context, setConfig);
        if ((fieldsInSet == null || fieldsInSet.size() <= 0) && setConfig.getChildrenAsList().size() <= 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("Ignoring set \"" + setConfig.getSetId() + "\" as it does not have any fields or child sets");
            }
        } else {
            set = this.generateSetModel(context, setConfig, fieldsInSet);
            Iterator var5 = setConfig.getChildrenAsList().iterator();

            while(var5.hasNext()) {
                FormSet childSetConfig = (FormSet)var5.next();
                Set childSet = this.generateSetModelUsingVisibleFields(context, childSetConfig);
                set.addChild(childSet);
            }
        }

        return set;
    }

    protected Set generateSetModelUsingServerFields(ModelContext context, FormSet setConfig, Map<String, List<String>> setMembership) {
        Set set = null;
        List<String> fieldsInSet = (List)setMembership.get(setConfig.getSetId());
        if ((fieldsInSet == null || fieldsInSet.size() <= 0) && setConfig.getChildrenAsList().size() <= 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("Ignoring set \"" + setConfig.getSetId() + "\" as it does not have any fields or child sets");
            }
        } else {
            set = this.generateSetModel(context, setConfig, fieldsInSet);
            Iterator var6 = setConfig.getChildrenAsList().iterator();

            while(var6.hasNext()) {
                FormSet childSetConfig = (FormSet)var6.next();
                Set childSet = this.generateSetModelUsingServerFields(context, childSetConfig, setMembership);
                set.addChild(childSet);
            }
        }

        return set;
    }

    protected Set generateSetModel(ModelContext context, FormSet setConfig, List<String> fields) {
        Set set = new Set(setConfig);
        Iterator var5 = fields.iterator();

        while(var5.hasNext()) {
            String fieldName = (String)var5.next();
            FormField fieldConfig = (FormField)context.getFormConfig().getFields().get(fieldName);
            Field field = this.generateFieldModel(context, fieldName, fieldConfig);
            if (field != null) {
                set.addChild(new FieldPointer(field.getId()));
                context.getFields().put(field.getId(), field);
            }
        }

        return set;
    }

    protected Set generateDefaultSetModelUsingServerFields(ModelContext context) {
        if (logger.isDebugEnabled()) {
            logger.debug("No configuration was found therefore showing all fields in the default set...");
        }

        Set set = new Set("", this.retrieveMessage("form.default.set.label"));

        try {
            JSONObject data = context.getFormDefinition().getJSONObject("data");
            JSONObject definition = data.getJSONObject("definition");
            JSONArray fieldsFromServer = definition.getJSONArray("fields");

            for(int x = 0; x < fieldsFromServer.length(); ++x) {
                String fieldName = fieldsFromServer.getJSONObject(x).getString("name");
                Field field = this.generateFieldModel(context, fieldName, (FormField)null);
                if (field != null) {
                    set.addChild(new FieldPointer(field.getId()));
                    context.getFields().put(field.getId(), field);
                }
            }
        } catch (JSONException var9) {
            if (logger.isErrorEnabled()) {
                logger.error("Failed to generate default set from server fields", var9);
            }
        }

        return set;
    }

    protected Field generateFieldModel(ModelContext context, String fieldName, FormField fieldConfig) {
        if (logger.isDebugEnabled()) {
            logger.debug("Generating model for field \"" + fieldName + "\"");
        }

        Field field = null;

        try {
            if (this.isFieldAmbiguous(context, fieldName)) {
                field = this.generateTransientFieldModel(fieldName, "/org/alfresco/components/form/controls/ambiguous.ftl");
            } else {
                JSONObject fieldDefinition = this.discoverFieldDefinition(context, fieldName);
                if (fieldDefinition != null) {
                    field = new Field();
                    this.processFieldIdentification(context, field, fieldDefinition, fieldConfig);
                    this.processFieldState(context, field, fieldDefinition, fieldConfig);
                    this.processFieldText(context, field, fieldDefinition, fieldConfig);
                    this.processFieldData(context, field, fieldDefinition, fieldConfig);
                    this.processFieldControl(context, field, fieldDefinition, fieldConfig);
                    this.processFieldConstraints(context, field, fieldDefinition, fieldConfig);
                    this.processFieldContent(context, field, fieldDefinition, fieldConfig);
                } else {
                    field = this.generateTransientFieldModel(context, fieldName, fieldDefinition, fieldConfig);
                    if (field == null && logger.isDebugEnabled()) {
                        logger.debug("Ignoring field \"" + fieldName + "\" as neither a field definition or sufficient configuration could be located");
                    }
                }
            }
        } catch (JSONException var6) {
            if (logger.isErrorEnabled()) {
                logger.error("Failed to generate field model for \"" + fieldName + "\"", var6);
            }

            field = null;
        }

        return field;
    }

    protected boolean isFieldAmbiguous(ModelContext context, String fieldName) {
        boolean ambiguous = false;
        if (context.getPropertyDefinitions().get(fieldName) != null && context.getAssociationDefinitions().get(fieldName) != null) {
            ambiguous = true;
            if (logger.isWarnEnabled()) {
                logger.warn("\"" + fieldName + "\" is ambiguous, a property and an association exists with this name, prefix with either \"prop:\" or \"assoc:\" to uniquely identify the field");
            }
        }

        return ambiguous;
    }

    protected Field generateTransientFieldModel(String fieldName, String template) {
        Field field = new Field();
        String name = fieldName.replace(":", "_");
        field.setConfigName(fieldName);
        field.setName(name);
        field.setId(name);
        field.setLabel(fieldName);
        field.setValue("");
        field.setTransitory(true);
        field.setControl(new FieldControl(template));
        return field;
    }

    protected Field generateTransientFieldModel(ModelContext context, String fieldName, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        if (fieldConfig != null && fieldConfig.getControl() != null && fieldConfig.getControl().getTemplate() != null && fieldConfig.getAttributes() != null && (fieldConfig.getAttributes().get("set") == null || ((String)fieldConfig.getAttributes().get("set")).isEmpty())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Generating transient field for \"" + fieldName + "\"");
            }

            Field field = this.generateTransientFieldModel(fieldName, fieldConfig.getControl().getTemplate());
            List<ControlParam> params = fieldConfig.getControl().getParamsAsList();
            if (params.size() > 0) {
                FieldControl control = field.getControl();
                Iterator var8 = params.iterator();

                while(var8.hasNext()) {
                    ControlParam param = (ControlParam)var8.next();
                    control.getParams().put(param.getName(), param.getValue());
                }
            }

            this.processFieldText(context, field, fieldDefinition, fieldConfig);
            return field;
        } else {
            return null;
        }
    }

    protected void processFieldIdentification(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        field.setConfigName(fieldDefinition.getString("name"));
        field.setType(fieldDefinition.getString("type"));
        String name = field.getConfigName();
        if (field.getType().equals("association")) {
            if (!name.startsWith("assoc:")) {
                name = "assoc:" + field.getConfigName();
            }
        } else if (!name.startsWith("prop:")) {
            name = "prop:" + field.getConfigName();
        }

        name = name.replace(":", "_");
        field.setId(name);
        name = name.replace(".", "#dot#");
        field.setName(name);
    }

    protected void processFieldState(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        boolean disabled = false;
        if (fieldDefinition.has("protectedField")) {
            disabled = fieldDefinition.getBoolean("protectedField");
        }

        if (!disabled && fieldConfig != null && fieldConfig.isReadOnly()) {
            disabled = true;
        }

        field.setDisabled(disabled);
        boolean mandatory = false;
        if (fieldDefinition.has("mandatory")) {
            mandatory = fieldDefinition.getBoolean("mandatory");
        }

        if (fieldDefinition.has("endpointMandatory")) {
            mandatory = fieldDefinition.getBoolean("endpointMandatory");
        }

        if (!mandatory && fieldConfig != null && fieldConfig.isMandatory()) {
            mandatory = true;
        }

        field.setMandatory(mandatory);
        if (fieldDefinition.has("repeating")) {
            field.setRepeating(fieldDefinition.getBoolean("repeating"));
        }

        if (fieldDefinition.has("endpointMany")) {
            field.setRepeating(fieldDefinition.getBoolean("endpointMany"));
        }

        if (fieldDefinition.has("endpointDirection")) {
            field.setEndpointDirection(fieldDefinition.getString("endpointDirection"));
        }

    }

    protected void processFieldText(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        if (fieldDefinition != null) {
            if (fieldDefinition.has("label")) {
                field.setLabel(fieldDefinition.getString("label"));
            }

            if (fieldDefinition.has("description")) {
                field.setDescription(fieldDefinition.getString("description"));
            }
        }

        if (fieldConfig != null) {
            String configLabel = null;
            if (fieldConfig.getLabelId() != null) {
                configLabel = this.retrieveMessage(fieldConfig.getLabelId());
            } else if (fieldConfig.getLabel() != null) {
                configLabel = fieldConfig.getLabel();
            }

            if (configLabel != null) {
                field.setLabel(configLabel);
            }

            String configDesc = null;
            if (fieldConfig.getDescriptionId() != null) {
                configDesc = this.retrieveMessage(fieldConfig.getDescriptionId());
            } else if (fieldConfig.getDescription() != null) {
                configDesc = fieldConfig.getDescription();
            }

            if (configDesc != null) {
                field.setDescription(configDesc);
            }

            String configHelp = null;
            if (fieldConfig.getHelpTextId() != null) {
                configHelp = this.retrieveMessage(fieldConfig.getHelpTextId());
            } else if (fieldConfig.getHelpText() != null) {
                configHelp = fieldConfig.getHelpText();
            }

            if (configHelp != null) {
                field.setHelp(configHelp);
            }

            if (fieldConfig.getHelpEncodeHtml() != null) {
                field.setHelpEncodeHtml(fieldConfig.getHelpEncodeHtml().equalsIgnoreCase("true"));
            }
        }

    }

    protected void processFieldData(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        if (fieldDefinition.has("dataType")) {
            field.setDataType(fieldDefinition.getString("dataType"));
        }

        if (fieldDefinition.has("endpointType")) {
            field.setDataType(fieldDefinition.getString("endpointType"));
        }

        field.setDataKeyName(fieldDefinition.getString("dataKeyName"));
        field.setValue("");
        JSONObject formDefinition = context.getFormDefinition().getJSONObject("data");
        if (formDefinition.has("formData")) {
            JSONObject formData = formDefinition.getJSONObject("formData");
            if (formData.has(field.getDataKeyName())) {
                field.setValue(formData.get(field.getDataKeyName()));
            }
        }

        if (field.getValue().equals("") && context.getMode().equals(Mode.CREATE) && fieldDefinition.has("defaultValue")) {
            field.setValue(fieldDefinition.getString("defaultValue"));
        }

        if (fieldDefinition.has("indexTokenisationMode") && fieldDefinition.getString("indexTokenisationMode").toUpperCase().equals("FALSE")) {
            field.setIndexTokenisationMode(fieldDefinition.getString("indexTokenisationMode"));
        }

    }

    protected void processFieldConstraints(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        if (!field.isDisabled()) {
            if (field.isMandatory()) {
                Constraint constraint = this.generateConstraintModel(context, field, fieldDefinition, fieldConfig, "MANDATORY");
                if (constraint != null) {
                    context.getConstraints().add(constraint);
                }
            }

            if (fieldConfig != null && fieldConfig.getConstraintDefinitionMap() != null) {
                Map<String, ConstraintHandlerDefinition> fieldConstraints = fieldConfig.getConstraintDefinitionMap();
                Iterator var6 = fieldConstraints.keySet().iterator();

                while(var6.hasNext()) {
                    String constraintId = (String)var6.next();
                    Constraint constraint = null;
                    ConstraintHandlerDefinition customConstraintConfig = (ConstraintHandlerDefinition)fieldConstraints.get(constraintId);
                    if (customConstraintConfig != null) {
                        constraint = this.generateConstraintModel(context, field, fieldConfig, constraintId, new JSONObject(), customConstraintConfig);
                    }

                    if (constraint != null) {
                        context.getConstraints().add(constraint);
                    }
                }
            }
        }

        Constraint constraint;
        if (fieldDefinition.has("constraints")) {
            JSONArray constraints = fieldDefinition.getJSONArray("constraints");

            for(int x = 0; x < constraints.length(); ++x) {
                constraint = this.generateConstraintModel(context, field, fieldDefinition, fieldConfig, constraints.getJSONObject(x));
                if (constraint != null) {
                    context.getConstraints().add(constraint);
                }
            }
        }

        String dataType = field.getDataType();
        Map<String, ConstraintHandlerDefinition> constraintDefinitionMap = fieldConfig == null ? null : fieldConfig.getConstraintDefinitionMap();
        if (this.isConstraintHandlerExist(constraintDefinitionMap, "NUMBER") || this.isDataTypeNumber(dataType)) {
            constraint = this.generateConstraintModel(context, field, fieldDefinition, fieldConfig, "NUMBER");
            if (constraint != null) {
                if (field.isRepeating()) {
                    constraint.getJSONParams().put("repeating", true);
                }

                context.getConstraints().add(constraint);
            }
        }

    }

    private boolean isConstraintHandlerExist(Map<String, ConstraintHandlerDefinition> constraintDefinitionMap, String constraint) {
        return constraintDefinitionMap != null ? constraintDefinitionMap.containsKey(constraint) : false;
    }

    private boolean isDataTypeNumber(String dataType) {
        return "int".equals(dataType) || "long".equals(dataType) || "double".equals(dataType) || "float".equals(dataType);
    }

    protected Constraint generateConstraintModel(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig, String constraintId) throws JSONException {
        JSONObject constraintDef = new JSONObject();
        constraintDef.put("type", constraintId);
        return this.generateConstraintModel(context, field, fieldDefinition, fieldConfig, constraintDef);
    }

    protected Constraint generateConstraintModel(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig, JSONObject constraintDefinition) throws JSONException {
        Constraint constraint = null;
        String constraintId = null;
        JSONObject constraintParams = null;
        if (constraintDefinition.has("type")) {
            constraintId = constraintDefinition.getString("type");
        }

        if (constraintDefinition.has("parameters")) {
            constraintParams = constraintDefinition.getJSONObject("parameters");
        } else {
            constraintParams = new JSONObject();
        }

        ConstraintHandlersConfigElement defaultConstraintHandlers = null;
        FormsConfigElement formsGlobalConfig = (FormsConfigElement)this.configService.getGlobalConfig().getConfigElement("forms");
        if (formsGlobalConfig != null) {
            defaultConstraintHandlers = formsGlobalConfig.getConstraintHandlers();
        }

        if (defaultConstraintHandlers == null) {
            throw new WebScriptException("Failed to locate default constraint handlers configurarion");
        } else {
            ConstraintHandlerDefinition defaultConstraintConfig = (ConstraintHandlerDefinition)defaultConstraintHandlers.getItems().get(constraintId);
            if (defaultConstraintConfig != null) {
                constraint = this.generateConstraintModel(context, field, fieldConfig, constraintId, constraintParams, defaultConstraintConfig);
                this.processFieldConstraintControl(context, field, fieldConfig, constraint);
                this.processFieldConstraintHelp(context, field, fieldConfig, constraint);
            } else if (logger.isWarnEnabled()) {
                logger.warn("No default constraint configuration found for \"" + constraintId + "\" constraint whilst processing field \"" + field.getConfigName() + "\"");
            }

            return constraint;
        }
    }

    protected Constraint generateConstraintModel(ModelContext context, Field field, FormField fieldConfig, String constraintId, JSONObject constraintParams, ConstraintHandlerDefinition defaultConstraintConfig) throws JSONException {
        String validationHandler = defaultConstraintConfig.getValidationHandler();
        Constraint constraint = new Constraint(field.getId(), constraintId, validationHandler, constraintParams);
        if (defaultConstraintConfig.getEvent() != null) {
            constraint.setEvent(defaultConstraintConfig.getEvent());
        } else {
            constraint.setEvent("blur");
        }

        String constraintMsg = null;
        if (fieldConfig != null && fieldConfig.getConstraintDefinitionMap().get(constraintId) != null) {
            ConstraintHandlerDefinition fieldConstraintConfig = (ConstraintHandlerDefinition)fieldConfig.getConstraintDefinitionMap().get(constraintId);
            if (fieldConstraintConfig.getMessageId() != null) {
                constraintMsg = this.retrieveMessage(fieldConstraintConfig.getMessageId());
            } else if (fieldConstraintConfig.getMessage() != null) {
                constraintMsg = fieldConstraintConfig.getMessage();
            }

            if (fieldConstraintConfig.getValidationHandler() != null) {
                constraint.setValidationHandler(fieldConstraintConfig.getValidationHandler());
            }

            if (fieldConstraintConfig.getEvent() != null) {
                constraint.setEvent(fieldConstraintConfig.getEvent());
            }
        } else if (defaultConstraintConfig.getMessageId() != null) {
            constraintMsg = this.retrieveMessage(defaultConstraintConfig.getMessageId());
        } else if (defaultConstraintConfig.getMessage() != null) {
            constraintMsg = defaultConstraintConfig.getMessage();
        }

        if (constraintMsg == null) {
            constraintMsg = this.retrieveMessage(validationHandler + ".message");
        }

        if (constraintMsg != null) {
            constraint.setMessage(constraintMsg);
        }

        return constraint;
    }

    protected void processFieldConstraintControl(ModelContext context, Field field, FormField fieldConfig, Constraint constraint) throws JSONException {
        if ("LIST".equals(constraint.getId())) {
            if (fieldConfig == null || fieldConfig.getControl() == null || fieldConfig.getControl().getTemplate() == null) {
                if (field.isRepeating()) {
                    field.getControl().setTemplate("/org/alfresco/components/form/controls/selectmany.ftl");
                } else {
                    field.getControl().setTemplate("/org/alfresco/components/form/controls/selectone.ftl");
                }
            }

            if (!field.getControl().getParams().containsKey("options")) {
                JSONArray options = constraint.getJSONParams().getJSONArray("allowedValues");
                List<String> optionsList = new ArrayList(options.length());

                for(int x = 0; x < options.length(); ++x) {
                    optionsList.add(options.getString(x));
                }

                if (fieldConfig != null && fieldConfig.isSorted()) {
                    Collections.sort(optionsList, new OptionsComparator());
                }

                field.getControl().getParams().put("options", StringUtils.collectionToDelimitedString(optionsList, "#alf#"));
                field.getControl().getParams().put("optionSeparator", "#alf#");
            }
        } else if ("LENGTH".equals(constraint.getId())) {
            int maxLength = -1;
            if (constraint.getJSONParams().has("maxLength")) {
                maxLength = constraint.getJSONParams().getInt("maxLength");
            }

            if (maxLength != -1) {
                field.getControl().getParams().put("maxLength", Integer.toString(maxLength));
                constraint.getJSONParams().put("crop", true);
            }
        } else if ("REGEX".equals(constraint.getId()) && "prop_cm_name".equals(field.getName())) {
            constraint.setValidationHandler("Alfresco.forms.validation.fileName");
            constraint.setJSONParams(new JSONObject());
        }

    }

    protected void processFieldConstraintHelp(ModelContext context, Field field, FormField fieldConfig, Constraint constraint) throws JSONException {
        if (field.getHelp() == null) {
            String text;
            if ("LENGTH".equals(constraint.getId())) {
                text = this.retrieveMessage("form.field.constraint.length", constraint.getJSONParams().getInt("minLength"), constraint.getJSONParams().getInt("maxLength"));
                field.setHelp(text);
            } else if ("MINMAX".equals(constraint.getId())) {
                text = this.retrieveMessage("form.field.constraint.minmax", constraint.getJSONParams().getInt("minValue"), constraint.getJSONParams().getInt("maxValue"));
                field.setHelp(text);
            } else if ("NUMBER".equals(constraint.getId())) {
                field.setHelp(this.retrieveMessage("form.field.constraint.number"));
            }
        }

    }

    protected void processFieldControl(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        FieldControl control = null;
        DefaultControlsConfigElement defaultControls = null;
        FormsConfigElement formsGlobalConfig = (FormsConfigElement)this.configService.getGlobalConfig().getConfigElement("forms");
        if (formsGlobalConfig != null) {
            defaultControls = formsGlobalConfig.getDefaultControls();
        }

        if (defaultControls == null) {
            throw new WebScriptException("Failed to locate default controls configuration");
        } else {
            boolean isPropertyField = !"association".equals(fieldDefinition.getString("type"));
            Control defaultControlConfig = null;
            if (isPropertyField) {
                defaultControlConfig = (Control)defaultControls.getItems().get(fieldDefinition.getString("dataType"));
                if (defaultControlConfig == null) {
                    defaultControlConfig = (Control)defaultControls.getItems().get("d:" + fieldDefinition.getString("dataType"));
                }
            } else {
                defaultControlConfig = (Control)defaultControls.getItems().get("association:" + fieldDefinition.getString("endpointType"));
                if (defaultControlConfig == null) {
                    defaultControlConfig = (Control)defaultControls.getItems().get("association");
                }
            }

            if (fieldConfig != null && fieldConfig.getControl() != null && fieldConfig.getControl().getTemplate() != null) {
                control = new FieldControl(fieldConfig.getControl().getTemplate());
            } else if (defaultControlConfig != null) {
                control = new FieldControl(defaultControlConfig.getTemplate());
            } else if (logger.isWarnEnabled()) {
                if (isPropertyField) {
                    Log var10000 = logger;
                    String var10001 = fieldDefinition.getString("dataType");
                    var10000.warn("No default control found for data type \"" + var10001 + "\" whilst processing field \"" + fieldDefinition.getString("name") + "\"");
                } else {
                    logger.warn("No default control found for associations\" whilst processing field \"" + fieldDefinition.getString("name") + "\"");
                }
            }

            if (isPropertyField && control != null && fieldDefinition.has("dataTypeParameters")) {
                control.getParams().put("dataTypeParameters", fieldDefinition.get("dataTypeParameters").toString());
            }

            List paramsConfig;
            Iterator var11;
            ControlParam param;
            if (defaultControlConfig != null && control != null) {
                paramsConfig = defaultControlConfig.getParamsAsList();
                var11 = paramsConfig.iterator();

                while(var11.hasNext()) {
                    param = (ControlParam)var11.next();
                    control.getParams().put(param.getName(), param.getValue());
                }
            }

            if (fieldConfig != null && control != null) {
                paramsConfig = fieldConfig.getControl().getParamsAsList();
                var11 = paramsConfig.iterator();

                while(var11.hasNext()) {
                    param = (ControlParam)var11.next();
                    control.getParams().put(param.getName(), param.getValue());
                }
            }

            field.setControl(control);
        }
    }

    protected void processFieldContent(ModelContext context, Field field, JSONObject fieldDefinition, FormField fieldConfig) throws JSONException {
        if (context.getFormUIModel().get("capabilities") != null && "content".equals(field.getDataType())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Retrieving content for \"" + field.getConfigName() + "\" as JavaScript is disabled");
            }

            String nodeRef = this.getParameter(context.getRequest(), "itemId");

            try {
                ConnectorService connService = FrameworkUtil.getConnectorService();
                RequestContext requestContext = ThreadLocalRequestContext.getRequestContext();
                String currentUserId = requestContext.getUserId();
                HttpSession currentSession = ServletUtil.getSession(true);
                Connector connector = connService.getConnector("alfresco", currentUserId, currentSession);
                Response response = connector.call("/api/node/content/" + nodeRef.replace("://", "/"));
                if (response.getStatus().getCode() == 200) {
                    field.setContent(response.getText());
                }
            } catch (Exception var12) {
                if (logger.isErrorEnabled()) {
                    logger.error("Failed to get field content: ", var12);
                }
            }
        }

    }

    protected Map<String, Object> generateErrorModel(Response errorResponse) {
        return this.generateErrorModel(errorResponse, (String)null);
    }

    protected Map<String, Object> generateErrorModel(Response errorResponse, String errorKey) {
        String error = "";

        try {
            JSONObject json = new JSONObject(new JSONTokener(errorResponse.getResponse()));
            if (json.has("message")) {
                error = json.getString("message");
                if (error.indexOf("org.alfresco.repo.security.permissions.AccessDeniedException") == -1 && (errorKey == null || errorKey.isEmpty()) && logger.isErrorEnabled()) {
                    logger.error(error);
                }
            }
        } catch (JSONException var6) {
            error = "";
        }

        if (errorKey == null || errorKey.isEmpty()) {
            errorKey = "form.error";
        }

        String id = errorKey + "." + errorResponse.getStatus().getCode();
        error = this.retrieveMessage(id);
        if (error.equals(id)) {
            error = this.retrieveMessage(errorKey);
        }

        Map<String, Object> model = new HashMap(1);
        model.put("error", error);
        return model;
    }

    protected void dumpFormUIModel(Map<String, Object> model) {
        if (logger.isDebugEnabled()) {
            Log var10000 = logger;
            String var10001 = this.dumpMap(model, "   ");
            var10000.debug("formUIModel = " + var10001);
        }

    }

    protected String dumpMap(Map<String, Object> map, String indent) {
        StringBuilder builder = new StringBuilder();
        builder.append("\n");
        if (indent.length() > "   ".length()) {
            builder.append(indent.substring("   ".length()));
        }

        builder.append("{");
        boolean firstKey = true;
        Iterator var5 = map.keySet().iterator();

        while(true) {
            while(var5.hasNext()) {
                String key = (String)var5.next();
                if (firstKey) {
                    firstKey = false;
                } else {
                    builder.append(",");
                }

                builder.append("\n");
                builder.append(indent);
                builder.append(key);
                builder.append(": ");
                Object value = map.get(key);
                if (value instanceof String) {
                    builder.append("\"");
                    builder.append(value);
                    builder.append("\"");
                } else if (value instanceof Map) {
                    builder.append(this.dumpMap((Map)value, indent + "   "));
                } else if (!(value instanceof List)) {
                    builder.append(value);
                } else {
                    boolean firstItem = true;
                    builder.append("\n").append("   ").append("[");
                    Iterator var9 = ((List)value).iterator();

                    while(var9.hasNext()) {
                        Object item = var9.next();
                        if (firstItem) {
                            firstItem = false;
                        } else {
                            builder.append(",");
                        }

                        builder.append("\n").append("   ").append("   ");
                        builder.append(item);
                    }

                    builder.append("\n").append("   ").append("]");
                }
            }

            builder.append("\n");
            if (indent.length() > "   ".length()) {
                builder.append(indent.substring("   ".length()));
            }

            builder.append("}");
            return builder.toString();
        }
    }

    protected class MessageHelper extends AbstractMessageHelper {
        public MessageHelper(WebScript webscript) {
            super(webscript);
        }

        public String get(String id, Object... args) {
            return this.resolveMessage(id, args);
        }
    }

    protected class ModelContext {
        private Map<String, Object> formUIModel;
        private Map<String, JSONObject> propDefs;
        private Map<String, JSONObject> assocDefs;
        private WebScriptRequest request;
        private Mode mode;
        private JSONObject formDefinition;
        private FormConfigElement formConfig;
        private List<Constraint> constraints;
        private List<Element> structure;
        private Map<String, Field> fields;

        protected ModelContext(WebScriptRequest request, Mode mode, JSONObject formDefinition, FormConfigElement formConfig) {
            this.request = request;
            this.mode = mode;
            this.formDefinition = formDefinition;
            this.formConfig = formConfig;
            this.cacheFieldDefinitions();
        }

        public void cacheFieldDefinitions() {
            this.propDefs = new HashMap(8);
            this.assocDefs = new HashMap(8);

            try {
                JSONObject data = this.formDefinition.getJSONObject("data");
                JSONObject definition = data.getJSONObject("definition");
                JSONArray fields = definition.getJSONArray("fields");

                for(int x = 0; x < fields.length(); ++x) {
                    JSONObject fieldDef = fields.getJSONObject(x);
                    if (fieldDef.getString("type").equals("property")) {
                        this.propDefs.put(fieldDef.getString("name"), fieldDef);
                    } else if (fieldDef.getString("type").equals("association")) {
                        this.assocDefs.put(fieldDef.getString("name"), fieldDef);
                    }
                }
            } catch (JSONException var6) {
                if (FormUIGet.logger.isErrorEnabled()) {
                    FormUIGet.logger.error("Failed to cache field definitions", var6);
                }
            }

        }

        public void setFormUIModel(Map<String, Object> formUIModel) {
            this.formUIModel = formUIModel;
        }

        public Map<String, Object> getFormUIModel() {
            return this.formUIModel;
        }

        public Map<String, JSONObject> getPropertyDefinitions() {
            return this.propDefs;
        }

        public Map<String, JSONObject> getAssociationDefinitions() {
            return this.assocDefs;
        }

        public WebScriptRequest getRequest() {
            return this.request;
        }

        public Mode getMode() {
            return this.mode;
        }

        public JSONObject getFormDefinition() {
            return this.formDefinition;
        }

        public FormConfigElement getFormConfig() {
            return this.formConfig;
        }

        public List<Constraint> getConstraints() {
            if (this.constraints == null) {
                this.constraints = new ArrayList(2);
            }

            return this.constraints;
        }

        public List<Element> getStructure() {
            if (this.structure == null) {
                this.structure = new ArrayList(4);
            }

            return this.structure;
        }

        public Map<String, Field> getFields() {
            if (this.fields == null) {
                this.fields = new HashMap(8);
            }

            return this.fields;
        }
    }

    public class Constraint {
        private String fieldId;
        private String id;
        private String validationHandler;
        private JSONObject params;
        private String message;
        private String event;

        Constraint(String fieldId, String id, String handler, JSONObject params) {
            this.fieldId = fieldId;
            this.id = id;
            this.validationHandler = handler;
            this.params = params;
        }

        public String getFieldId() {
            return this.fieldId;
        }

        public String getId() {
            return this.id;
        }

        public String getValidationHandler() {
            return this.validationHandler;
        }

        public void setValidationHandler(String validationHandler) {
            this.validationHandler = validationHandler;
        }

        public String getParams() {
            if (this.params == null) {
                this.params = new JSONObject();
            }

            return this.params.toString();
        }

        public JSONObject getJSONParams() {
            return this.params;
        }

        public void setJSONParams(JSONObject params) {
            this.params = params;
        }

        public String getMessage() {
            return this.message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getEvent() {
            return this.event;
        }

        public void setEvent(String event) {
            this.event = event;
        }

        public String toString() {
            StringBuilder buffer = new StringBuilder();
            buffer.append("constraint(fieldId=").append(this.fieldId);
            buffer.append(" id=").append(this.id);
            buffer.append(" validationHandler=").append(this.validationHandler);
            buffer.append(" event=").append(this.event);
            buffer.append(" message=").append(this.message);
            buffer.append(")");
            return buffer.toString();
        }
    }

    public class Set extends Element {
        protected String appearance;
        protected String template;
        protected String label;
        protected List<Element> children;

        Set(FormSet setConfig) {
            super();
            this.kind = "set";
            this.id = setConfig.getSetId();
            this.appearance = setConfig.getAppearance();
            this.template = setConfig.getTemplate();
            this.label = FormUIGet.this.discoverSetLabel(setConfig);
            this.children = new ArrayList(4);
        }

        Set(String id, String label) {
            super();
            this.kind = "set";
            this.id = id;
            this.label = label;
            this.children = new ArrayList(1);
        }

        public void addChild(Element child) {
            this.children.add(child);
        }

        public String getAppearance() {
            return this.appearance;
        }

        public String getTemplate() {
            return this.template;
        }

        public String getLabel() {
            return this.label;
        }

        public List<Element> getChildren() {
            return this.children;
        }

        public String toString() {
            StringBuilder buffer = new StringBuilder();
            buffer.append(this.kind);
            buffer.append("(id=").append(this.id);
            buffer.append(" appearance=").append(this.appearance);
            buffer.append(" label=").append(this.label);
            buffer.append(" template=").append(this.template);
            buffer.append(" children=[");
            boolean first = true;

            Element child;
            for(Iterator var3 = this.children.iterator(); var3.hasNext(); buffer.append(child)) {
                child = (Element)var3.next();
                if (first) {
                    first = false;
                } else {
                    buffer.append(", ");
                }
            }

            buffer.append("])");
            return buffer.toString();
        }
    }

    public abstract class Element {
        protected String kind;
        protected String id;

        public Element() {
        }

        public String getKind() {
            return this.kind;
        }

        public String getId() {
            return this.id;
        }

        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append(this.kind);
            builder.append("(");
            builder.append(this.id);
            builder.append(")");
            return builder.toString();
        }
    }

    public class Field extends Element {
        protected String name;
        protected String configName;
        protected String label;
        protected String description;
        protected String help;
        protected boolean helpEncodeHtml = true;
        protected FieldControl control;
        protected String dataKeyName;
        protected String dataType;
        protected String type;
        protected String content;
        protected String endpointDirection;
        protected Object value;
        protected boolean disabled = false;
        protected boolean mandatory = false;
        protected boolean transitory = false;
        protected boolean repeating = false;
        protected String indexTokenisationMode;

        Field() {
            super();
            this.kind = "field";
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getConfigName() {
            return this.configName;
        }

        public void setConfigName(String configName) {
            this.configName = configName;
        }

        public FieldControl getControl() {
            return this.control;
        }

        public void setControl(FieldControl control) {
            this.control = control;
        }

        public String getDataKeyName() {
            return this.dataKeyName;
        }

        public void setDataKeyName(String dataKeyName) {
            this.dataKeyName = dataKeyName;
        }

        public String getDataType() {
            return this.dataType;
        }

        public void setDataType(String dataType) {
            this.dataType = dataType;
        }

        public String getDescription() {
            return this.description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public boolean isDisabled() {
            return this.disabled;
        }

        public void setDisabled(boolean disabled) {
            this.disabled = disabled;
        }

        public String getLabel() {
            return this.label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public boolean isMandatory() {
            return this.mandatory;
        }

        public void setMandatory(boolean mandatory) {
            this.mandatory = mandatory;
        }

        public boolean isTransitory() {
            return this.transitory;
        }

        public void setTransitory(boolean transitory) {
            this.transitory = transitory;
        }

        public String getName() {
            return this.name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isRepeating() {
            return this.repeating;
        }

        public void setRepeating(boolean repeating) {
            this.repeating = repeating;
        }

        public String getType() {
            return this.type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public Object getValue() {
            return this.value;
        }

        public void setValue(Object value) {
            this.value = value;
        }

        public String getContent() {
            return this.content;
        }

        public void setContent(String content) {
            this.content = content;
        }

        public String getHelp() {
            return this.help;
        }

        public void setHelp(String help) {
            this.help = help;
        }

        public boolean getHelpEncodeHtml() {
            return this.helpEncodeHtml;
        }

        public void setHelpEncodeHtml(boolean encode) {
            this.helpEncodeHtml = encode;
        }

        public String getEndpointDirection() {
            return this.endpointDirection;
        }

        public void setEndpointDirection(String endpointDirection) {
            this.endpointDirection = endpointDirection;
        }

        public String getEndpointType() {
            return this.getDataType();
        }

        public boolean isEndpointMandatory() {
            return this.mandatory;
        }

        public boolean isEndpointMany() {
            return this.repeating;
        }

        public String getIndexTokenisationMode() {
            return this.indexTokenisationMode;
        }

        public void setIndexTokenisationMode(String indexTokenisationMode) {
            this.indexTokenisationMode = indexTokenisationMode;
        }

        public String toString() {
            StringBuilder buffer = new StringBuilder();
            buffer.append(this.kind);
            buffer.append("(id=").append(this.id);
            buffer.append(" name=").append(this.name);
            buffer.append(" configName=").append(this.configName);
            buffer.append(" type=").append(this.type);
            buffer.append(" value=").append(this.value);
            buffer.append(" label=").append(this.label);
            buffer.append(" description=").append(this.description);
            buffer.append(" help=").append(this.help);
            buffer.append(" helpEncodeHtml=").append(this.helpEncodeHtml);
            buffer.append(" dataKeyName=").append(this.dataKeyName);
            buffer.append(" dataType=").append(this.dataType);
            buffer.append(" endpointDirection=").append(this.endpointDirection);
            buffer.append(" disabled=").append(this.disabled);
            buffer.append(" mandatory=").append(this.mandatory);
            buffer.append(" repeating=").append(this.repeating);
            buffer.append(" transitory=").append(this.transitory);
            buffer.append(" indexTokenisationMode=").append(this.indexTokenisationMode);
            buffer.append(" ").append(this.control);
            buffer.append(")");
            return buffer.toString();
        }
    }

    public class FieldPointer extends Element {
        FieldPointer(String id) {
            super();
            this.kind = "field";
            this.id = id;
        }
    }

    public class FieldControl {
        protected String template;
        protected Map<String, String> params;

        FieldControl(String template) {
            this.template = template;
            this.params = new HashMap(4);
        }

        public String getTemplate() {
            return this.template;
        }

        public void setTemplate(String template) {
            this.template = template;
        }

        public Map<String, String> getParams() {
            return this.params;
        }

        public String toString() {
            StringBuilder buffer = new StringBuilder();
            buffer.append("control(template=").append(this.template);
            buffer.append(" params=").append(this.params);
            buffer.append(")");
            return buffer.toString();
        }
    }
}
