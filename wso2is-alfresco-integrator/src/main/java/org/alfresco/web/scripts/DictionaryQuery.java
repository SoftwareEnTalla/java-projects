//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.ParameterCheck;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.extensions.surf.ClusterMessageAware;
import org.springframework.extensions.surf.ClusterService;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.Response;

public class DictionaryQuery extends SingletonValueProcessorExtension<Dictionary> implements Serializable, ClusterMessageAware {
    private static Log logger = LogFactory.getLog(DictionaryQuery.class);
    protected ClusterService clusterService;

    public DictionaryQuery() {
    }

    public String[] getAllAspects() {
        return this.getDictionary().getAllAspects();
    }

    public String[] getAllTypes() {
        return this.getDictionary().getAllTypes();
    }

    public boolean isSubType(String type, String isType) {
        ParameterCheck.mandatoryString("type", type);
        ParameterCheck.mandatoryString("isType", isType);
        return type.equals(isType) || this.getDictionary().isSubType(type, isType);
    }

    public String[] getSubTypes(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getSubTypes(ddclass);
    }

    public boolean hasDefaultAspect(String type, String aspect) {
        ParameterCheck.mandatoryString("type", type);
        ParameterCheck.mandatoryString("aspect", aspect);
        return this.getDictionary().hasDefaultAspect(type, aspect);
    }

    public String[] getDefaultAspects(String type) {
        ParameterCheck.mandatoryString("type", type);
        return this.getDictionary().getDefaultAspects(type);
    }

    public boolean isAspect(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getAspect(ddclass) != null;
    }

    public boolean isType(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getType(ddclass) != null;
    }

    public boolean hasProperty(String ddclass, String property) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        ParameterCheck.mandatoryString("property", property);
        return this.getDictionary().hasProperty(ddclass, property, false);
    }

    public boolean hasProperty(String ddclass, String property, boolean includeDefaultAspects) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        ParameterCheck.mandatoryString("property", property);
        return this.getDictionary().hasProperty(ddclass, property, true);
    }

    public String getTitle(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getTitle(ddclass);
    }

    public String getDescription(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getDescription(ddclass);
    }

    public String getParent(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getParent(ddclass);
    }

    public boolean isContainer(String type) {
        ParameterCheck.mandatoryString("type", type);
        return this.getDictionary().isContainer(type);
    }

    public Dictionary.DictionaryProperty getProperty(String ddclass, String property) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        ParameterCheck.mandatoryString("property", property);
        return this.getDictionary().getProperty(ddclass, property, false);
    }

    public Dictionary.DictionaryProperty getProperty(String ddclass, String property, boolean includeDefaultAspects) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        ParameterCheck.mandatoryString("property", property);
        return this.getDictionary().getProperty(ddclass, property, true);
    }

    public Dictionary.DictionaryProperty[] getProperties(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getProperties(ddclass, false);
    }

    public Dictionary.DictionaryProperty[] getProperties(String ddclass, boolean includeDefaultAspects) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getProperties(ddclass, true);
    }

    public Dictionary.DictionaryAssoc[] getAssociations(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getAssociations(ddclass);
    }

    public Dictionary.DictionaryAssoc[] getChildAssociations(String ddclass) {
        ParameterCheck.mandatoryString("ddclass", ddclass);
        return this.getDictionary().getChildAssociations(ddclass);
    }

    public void updateAddClasses(String json) {
        ParameterCheck.mandatoryString("json", json);
        this.getDictionary().updateAddClasses(json);
        if (this.clusterService != null) {
            Map<String, Serializable> params = new HashMap(4);
            params.put("add", json);
            params.put("user", ThreadLocalRequestContext.getRequestContext().getUserId());
            this.clusterService.publishClusterMessage("dictionary-update", params);
        }

    }

    public void updateRemoveClasses(String json) {
        ParameterCheck.mandatoryString("json", json);
        this.getDictionary().updateRemoveClasses(json);
        if (this.clusterService != null) {
            Map<String, Serializable> params = new HashMap(4);
            params.put("remove", json);
            params.put("user", ThreadLocalRequestContext.getRequestContext().getUserId());
            this.clusterService.publishClusterMessage("dictionary-update", params);
        }

    }

    public String toString() {
        try {
            String out = "";
            RequestContext rc = ThreadLocalRequestContext.getRequestContext();
            String userId = rc.getUserId();
            if (userId != null && !AuthenticationUtil.isGuest(userId)) {
                int idx = userId.indexOf(64);
                if (idx != -1) {
                    String var10000 = userId.substring(idx);
                    out = "Dictionary for user domain: " + var10000 + "\r\n";
                }
            }

            return out + this.getDictionary().toString();
        } catch (Throwable var5) {
            return super.toString();
        }
    }

    private Dictionary getDictionary() {
        return (Dictionary)this.getSingletonValue(this.isTenant());
    }

    protected boolean isTenant() {
        return true;
    }

    protected Dictionary retrieveValue(String userId, String storeId) throws ConnectorServiceException {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", userId, ServletUtil.getSession());
        Response response = conn.call("/api/dictionary");
        if (response.getStatus().getCode() == 200) {
            Log var10000 = logger;
            String var10001 = storeId.length() != 0 ? " - for domain: " + storeId : "";
            var10000.info("Successfully retrieved Data Dictionary from Alfresco." + var10001);
            Map<String, Dictionary.DictionaryItem> types = new HashMap(128);
            Map<String, Dictionary.DictionaryItem> aspects = new HashMap(128);

            try {
                JSONArray json = new JSONArray(response.getResponse());

                for(int i = 0; i < json.length(); ++i) {
                    JSONObject ddclass = json.getJSONObject(i);
                    String typeName = ddclass.getString("name");
                    if (ddclass.getBoolean("isAspect")) {
                        aspects.put(typeName, new Dictionary.DictionaryItem(typeName, ddclass));
                    } else {
                        types.put(typeName, new Dictionary.DictionaryItem(typeName, ddclass));
                    }
                }
            } catch (JSONException var13) {
                throw new AlfrescoRuntimeException(var13.getMessage(), var13);
            }

            Dictionary dictionary = new Dictionary(types, aspects);
            return dictionary;
        } else {
            throw new AlfrescoRuntimeException("Unable to retrieve dictionary information from Alfresco: " + response.getStatus().getCode());
        }
    }

    protected String getValueName() {
        return "dictionary information";
    }

    public void setClusterService(ClusterService service) {
        this.clusterService = service;
    }

    public String getClusterMessageType() {
        return "dictionary-update";
    }

    public void onClusterMessage(Map<String, Serializable> payload) {
        String userId = (String)payload.get("user");
        String jsonAdd = (String)payload.get("add");
        String jsonRemove = (String)payload.get("add");
        if (jsonAdd != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Cluster message to update dictionary with ADD operation: " + jsonAdd);
            }

            if (this.hasSingletonValue(this.isTenant(), userId)) {
                ((Dictionary)this.getSingletonValue(this.isTenant(), userId)).updateAddClasses(jsonAdd);
            }
        }

        if (jsonRemove != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Cluster message to update dictionary with REMOVE operation: " + jsonRemove);
            }

            if (this.hasSingletonValue(this.isTenant(), userId)) {
                ((Dictionary)this.getSingletonValue(this.isTenant(), userId)).updateRemoveClasses(jsonRemove);
            }
        }

    }

    interface DictionaryUpdateMessage {
        String TYPE = "dictionary-update";
        String PAYLOAD_ADD = "add";
        String PAYLOAD_REMOVE = "remove";
        String PAYLOAD_USERID = "user";
    }
}
