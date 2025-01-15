//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.HashMap;
import org.alfresco.error.AlfrescoRuntimeException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.ParseException;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;

public abstract class BaseEvaluator implements Evaluator {
    private static final String PORTLET_HOST = "portletHost";
    protected HashMap<String, String> args = null;
    protected JSONObject metadata = null;
    protected boolean negateOutput = false;

    public BaseEvaluator() {
    }

    public void setNegateOutput(boolean negateOutput) {
        this.negateOutput = negateOutput;
    }

    public final boolean evaluate(Object record) {
        return this.evaluate(record, (Object)null, (HashMap)null);
    }

    public final boolean evaluate(Object record, Object metadata) {
        return this.evaluate(record, metadata, (HashMap)null);
    }

    public final boolean evaluate(Object record, Object metadata, HashMap<String, String> args) {
        this.args = args;

        JSONObject jsonObject=null;
        try {
            // Validar y convertir 'record' en JSONObject
            if (record instanceof JSONObject) {
                jsonObject = (JSONObject) record;
            } else if (record instanceof String) {
                jsonObject = (JSONObject) JSONValue.parseWithException((String) record);
            } else {
                throw new IllegalArgumentException("Expecting either JSONObject or JSON String for 'record'");
            }

            // Validar y convertir 'metadata' en JSONObject
            if (metadata instanceof JSONObject) {
                this.metadata = (JSONObject) metadata;
            } else if (metadata instanceof String) {
                this.metadata = (JSONObject) JSONValue.parseWithException((String) metadata);
            } else {
                throw new IllegalArgumentException("Expecting either JSONObject or JSON String for 'metadata'");
            }
        } catch (ParseException e) {
            throw new AlfrescoRuntimeException("Failed to parse JSON string: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new AlfrescoRuntimeException("Failed to run UI evaluator: " + e.getMessage(), e);
        }

        // Evaluar y retornar el resultado
        return this.negateOutput ^ this.evaluate(jsonObject);
    }


    public abstract boolean evaluate(JSONObject var1);

    public final HashMap<String, String> getArgs() {
        return this.args;
    }

    public final String getArg(String name) {
        return this.args != null && this.args.containsKey(name) ? (String)this.args.get(name) : null;
    }

    public final JSONObject getMetadata() {
        return this.metadata;
    }

    public final String getHeader(String name) {
        String header = null;
        if (name != null) {
            RequestContext rc = ThreadLocalRequestContext.getRequestContext();
            header = rc.getHeader(name);
        }

        return header;
    }

    public final boolean getIsPortlet() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        return rc.getAttribute("portletHost") != null;
    }

    public final String getNodeType(JSONObject jsonObject) {
        String type = null;

        try {
            JSONObject node = (JSONObject)jsonObject.get("node");
            if (node != null) {
                type = (String)node.get("type");
            }

            return type;
        } catch (Exception var4) {
            throw new AlfrescoRuntimeException("Exception whilst running UI evaluator: " + var4.getMessage());
        }
    }

    public final String getNodeMimetype(JSONObject jsonObject) {
        String mimetype = null;

        try {
            JSONObject node = (JSONObject)jsonObject.get("node");
            if (node != null) {
                mimetype = (String)node.get("mimetype");
            }

            return mimetype;
        } catch (Exception var4) {
            throw new AlfrescoRuntimeException("Exception whilst running UI evaluator: " + var4.getMessage());
        }
    }

    public final JSONArray getNodeAspects(JSONObject jsonObject) {
        JSONArray aspects = null;

        try {
            JSONObject node = (JSONObject)jsonObject.get("node");
            if (node != null) {
                aspects = (JSONArray)node.get("aspects");
            }

            return aspects;
        } catch (Exception var4) {
            throw new AlfrescoRuntimeException("Exception whilst running UI evaluator: " + var4.getMessage());
        }
    }

    public final Object getProperty(JSONObject jsonObject, String propertyName) {
        Object property = null;

        try {
            JSONObject node = (JSONObject)jsonObject.get("node");
            if (node != null) {
                JSONObject properties = (JSONObject)node.get("properties");
                if (properties != null) {
                    property = properties.get(propertyName);
                }
            }

            return property;
        } catch (Exception var6) {
            throw new AlfrescoRuntimeException("Exception whilst running UI evaluator: " + var6.getMessage());
        }
    }

    public final String getUserId() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        String userId = rc.getUserId();
        if (userId != null && !AuthenticationUtil.isGuest(userId)) {
            return userId;
        } else {
            throw new AlfrescoRuntimeException("User ID must exist and cannot be guest.");
        }
    }

    public final String getSiteId(JSONObject jsonObject) {
        String siteId = null;

        try {
            JSONObject location = (JSONObject)jsonObject.get("location");
            if (location != null) {
                JSONObject site = (JSONObject)location.get("site");
                if (site != null) {
                    siteId = (String)site.get("name");
                }
            }

            return siteId;
        } catch (Exception var5) {
            throw new AlfrescoRuntimeException("Exception whilst querying siteId from location: " + var5.getMessage());
        }
    }

    public final String getSitePreset(JSONObject jsonObject) {
        String sitePreset = null;

        try {
            JSONObject location = (JSONObject)jsonObject.get("location");
            if (location != null) {
                JSONObject site = (JSONObject)location.get("site");
                if (site != null) {
                    sitePreset = (String)site.get("preset");
                }
            }

            return sitePreset;
        } catch (Exception var5) {
            throw new AlfrescoRuntimeException("Exception whilst querying site preset from location: " + var5.getMessage());
        }
    }

    public final String getContainerType(JSONObject jsonObject) {
        String containerType = null;

        try {
            JSONObject location = (JSONObject)jsonObject.get("location");
            if (location != null) {
                JSONObject container = (JSONObject)location.get("container");
                if (container != null) {
                    containerType = (String)container.get("type");
                }
            }

            return containerType;
        } catch (Exception var5) {
            throw new AlfrescoRuntimeException("Exception whilst querying container type from location: " + var5.getMessage());
        }
    }

    public final boolean getIsLocked(JSONObject jsonObject) {
        boolean isLocked = false;
        JSONObject node = (JSONObject)jsonObject.get("node");
        if (node != null) {
            isLocked = (Boolean)node.get("isLocked");
        }

        return isLocked;
    }

    public final boolean getIsWorkingCopy(JSONObject jsonObject) {
        boolean isWorkingCopy = false;
        JSONObject workingCopy = (JSONObject)jsonObject.get("workingCopy");
        if (workingCopy != null) {
            isWorkingCopy = (Boolean)workingCopy.get("isWorkingCopy");
        }

        return isWorkingCopy;
    }

    public final boolean getMatchesCurrentUser(JSONObject jsonObject, String propertyName) {
        try {
            JSONObject user = (JSONObject)this.getProperty(jsonObject, propertyName);
            return user != null && user.get("userName").toString().equalsIgnoreCase(this.getUserId());
        } catch (Exception var4) {
            throw new AlfrescoRuntimeException("Exception whilst matching current user: " + var4.getMessage());
        }
    }

    public final Object getJSONValue(JSONObject jsonObject, String accessor) {
        String[] keys = accessor.split("\\.");
        Object record = jsonObject;
        String[] var5 = keys;
        int var6 = keys.length;

        for(int var7 = 0; var7 < var6; ++var7) {
            String key = var5[var7];
            if (record instanceof JSONObject) {
                record = ((JSONObject)record).get(key);
            } else {
                if (!(record instanceof JSONArray)) {
                    return null;
                }

                record = ((JSONArray)record).get(Integer.parseInt(key));
            }
        }

        return record;
    }

    public final boolean getHasContent(JSONObject jsonObject) {
        JSONObject node = (JSONObject)jsonObject.get("node");
        if (node != null) {
            return node.get("contentURL") != null;
        } else {
            return false;
        }
    }
}
