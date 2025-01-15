//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.Response;

public class MimetypesQuery extends SingletonValueProcessorExtension<Map<String, Mimetype>> implements Serializable {
    private static Log logger = LogFactory.getLog(MimetypesQuery.class);

    public MimetypesQuery() {
    }

    public Map<String, String> getDisplaysByMimetype() {
        Map<String, String> descriptions = new HashMap();
        Map<String, Mimetype> mimetypes = this.getMimetypes();
        Iterator var3 = mimetypes.values().iterator();

        while(var3.hasNext()) {
            Mimetype mimetype = (Mimetype)var3.next();
            descriptions.put(mimetype.getMimetype(), mimetype.getDescription());
        }

        return descriptions;
    }

    public Map<String, String> getMimetypesByDisplay() {
        Map<String, String> types = new TreeMap(new Comparator<String>() {
            public int compare(String o1, String o2) {
                return o1.toLowerCase().compareTo(o2.toLowerCase());
            }
        });
        Map<String, Mimetype> mimetypes = this.getMimetypes();
        Iterator var3 = mimetypes.values().iterator();

        while(var3.hasNext()) {
            Mimetype mimetype = (Mimetype)var3.next();
            types.put(mimetype.getDescription(), mimetype.getMimetype());
        }

        return types;
    }

    public String getExtension(String mimetype) {
        Mimetype mt = (Mimetype)this.getMimetypes().get(mimetype);
        return mt != null ? mt.getDefaultExtension() : null;
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
                    out = "Mimetypes for user domain: " + var10000 + "\r\n";
                }
            }

            return out + this.getMimetypes().toString();
        } catch (Throwable var5) {
            return super.toString();
        }
    }

    private Map<String, Mimetype> getMimetypes() {
        return (Map)this.getSingletonValue();
    }

    protected Map<String, Mimetype> retrieveValue(String userId, String storeId) throws ConnectorServiceException {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", userId, ServletUtil.getSession());
        Response response = conn.call("/api/mimetypes/descriptions");
        if (response.getStatus().getCode() == 200) {
            logger.info("Successfully retrieved mimetypes information from Alfresco.");
            Map<String, Mimetype> mimetypes = new HashMap(128);

            try {
                JSONObject json = new JSONObject(response.getResponse());
                JSONObject data = json.getJSONObject("data");
                Iterator<String> types = data.keys();

                while(types.hasNext()) {
                    String mimetype = (String)types.next();
                    Mimetype details = new Mimetype(mimetype, data.getJSONObject(mimetype));
                    mimetypes.put(mimetype, details);
                }

                return mimetypes;
            } catch (JSONException var12) {
                throw new AlfrescoRuntimeException(var12.getMessage(), var12);
            }
        } else {
            throw new AlfrescoRuntimeException("Unable to retrieve mimetypes information from Alfresco: " + response.getStatus().getCode());
        }
    }

    protected String getValueName() {
        return "mimetypes information";
    }
}
