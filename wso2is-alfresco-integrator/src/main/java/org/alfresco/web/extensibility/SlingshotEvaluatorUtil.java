//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import jakarta.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.WebFrameworkServiceRegistry;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.ScriptRemote;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.Response;

public class SlingshotEvaluatorUtil {
    private static Log logger = LogFactory.getLog(SlingshotEvaluatorUtil.class);
    public static final String SITE_PRESET_CACHE = SlingshotEvaluatorUtil.class.getName() + ".sitePresets";
    protected static final String PORTLET_HOST = "portletHost";
    protected static final String PORTLET_URL = "portletUrl";
    protected static final String SITE_PRESET = "sitePreset";
    protected static final String SITE = "site";
    protected static final String PAGE_CONTEXT = "pagecontext";
    protected WebFrameworkServiceRegistry serviceRegistry = null;

    public SlingshotEvaluatorUtil() {
    }

    public void setServiceRegistry(WebFrameworkServiceRegistry serviceRegistry) {
        this.serviceRegistry = serviceRegistry;
    }

    public String getEvaluatorParam(Map<String, String> params, String name, String defaultValue) {
        String value = (String)params.get(name);
        return value != null && !value.trim().isEmpty() ? value.trim() : defaultValue;
    }

    public Boolean getPortletHost(RequestContext context) {
        Boolean portletHost = (Boolean)context.getAttribute("portletHost");
        if (portletHost == null) {
            String portletHostParam = context.getParameter("portletHost");
            portletHost = portletHostParam != null && portletHostParam.equalsIgnoreCase("true");
        }

        return portletHost;
    }

    public String getPortletUrl(RequestContext context) {
        String portletUrl = (String)context.getAttribute("portletUrl");
        if (portletUrl == null) {
            portletUrl = context.getParameter("portletUrl");
        }

        return portletUrl;
    }

    public String getPageId(RequestContext context) {
        return context.getPageId();
    }

    public String getSite(RequestContext context) {
        String site = (String)context.getUriTokens().get("site");
        if (site == null) {
            site = context.getParameter("site");
        }

        if (site == null) {
            String[] pathNames = context.getUri().substring(context.getContextPath().length()).split("/");

            for(int i = 0; i < pathNames.length; ++i) {
                if (pathNames[i].equals("site") && i + 1 < pathNames.length) {
                    site = pathNames[i + 1];
                    break;
                }
            }
        }

        return site;
    }

    public String getPageContext(RequestContext context) {
        String pageContext = (String)context.getUriTokens().get("pagecontext");
        if (pageContext == null) {
            pageContext = context.getParameter("pagecontext");
        }

        if (pageContext == null) {
            String[] pathNames = context.getUri().substring(context.getContextPath().length()).split("/");

            for(int i = 0; i < pathNames.length; ++i) {
                if (pathNames[i].equals("pagecontext") && i + 1 < pathNames.length) {
                    pageContext = pathNames[i + 1];
                    break;
                }
            }
        }

        return pageContext;
    }

    public String getSitePreset(RequestContext context, String siteId) {
        HashMap sitePresetCache = (HashMap)context.getAttributes().get(SITE_PRESET_CACHE);
        if (sitePresetCache == null) {
            sitePresetCache = new HashMap();
            context.getAttributes().put(SITE_PRESET_CACHE, sitePresetCache);
        }

        String sitePresetId = (String)sitePresetCache.get(siteId);
        if (sitePresetId == null) {
            try {
                JSONObject site = this.jsonGet("/api/sites/" + URLEncoder.encode(siteId));
                if (site != null) {
                    sitePresetId = site.getString("sitePreset");
                    sitePresetCache.put(siteId, sitePresetId);
                }
            } catch (JSONException var6) {
                if (logger.isErrorEnabled()) {
                    logger.error("Could not get a sitePreset from site json.");
                }
            }
        }

        return sitePresetId;
    }

    public JSONObject jsonGet(String uri) {
        ScriptRemote scriptRemote = this.serviceRegistry.getScriptRemote();
        Response response = scriptRemote.connect().get(uri);
        if (response.getStatus().getCode() == 200) {
            try {
                return new JSONObject(response.getResponse());
            } catch (JSONException var5) {
                if (logger.isErrorEnabled()) {
                    logger.error("An error occurred when parsing response to json from the uri '" + uri + "': " + var5.getMessage());
                }
            }
        }

        return null;
    }

    public boolean isMemberOfGroups(RequestContext context, List<String> groups, boolean memberOfAllGroups) {
        Boolean isMember = null;
        HttpSession session = ServletUtil.getSession();
        JSONArray groupsList = null;
        String GROUP_MEMBERSHIPS = "AlfGroupMembershipsKey";
        String currentSite = this.getSite(context);
        boolean externalAuth = false;
        RemoteConfigElement config = (RemoteConfigElement)context.getServiceRegistry().getConfigService().getConfig("Remote").getConfigElement("remote");
        if (config != null) {
            RemoteConfigElement.EndpointDescriptor descriptor = config.getEndpointDescriptor("alfresco");
            if (descriptor != null) {
                externalAuth = descriptor.getExternalAuth();
            }
        }

        Object _cachedGroupMemberships = session.getAttribute(GROUP_MEMBERSHIPS);
        String userName;
        if (_cachedGroupMemberships instanceof JSONArray ) {
            ;
        } else {
            try {
                CredentialVault cv = context.getCredentialVault();
                if (cv != null) {
                    Credentials creds = cv.retrieve("alfresco");
                    if (creds == null && !externalAuth) {
                        return false;
                    }

                    userName = (String)session.getAttribute("_alf_USER_ID");
                    Connector connector = context.getServiceRegistry().getConnectorService().getConnector("alfresco", userName, ServletUtil.getSession());
                    Response res = connector.call("/api/people/" + URLEncoder.encode(context.getUserId()) + "?groups=true");
                    if (res.getStatus().getCode() == 200) {
                        userName = res.getResponse();
                        JSONParser p = new JSONParser();
                        Object o2 = p.parse(userName);
                        if (o2 instanceof org.json.simple.JSONObject) {
                            org.json.simple.JSONObject jsonRes = (org.json.simple.JSONObject)o2;
                            groupsList = (JSONArray)jsonRes.get("groups");
                            session.setAttribute(GROUP_MEMBERSHIPS, groupsList);
                        }
                    }
                }
            } catch (ConnectorServiceException var27) {
                var27.printStackTrace();
            } catch (ParseException var28) {
                var28.printStackTrace();
            }
        }

        Iterator var30 = groups.iterator();

        while(var30.hasNext()) {
            String groupName = (String)var30.next();
            boolean isMemberOfCurrentGroup = false;
            if (groupName != null) {
                if (groupName.startsWith("Site")) {
                    if (currentSite == null) {
                        isMember = false;
                    } else {
                        try {
                            CredentialVault cv = context.getCredentialVault();
                            if (cv != null) {
                                Credentials creds = cv.retrieve("alfresco");
                                if (creds == null && !externalAuth) {
                                    return false;
                                }

                                userName = (String)session.getAttribute("_alf_USER_ID");
                                Connector connector = context.getServiceRegistry().getConnectorService().getConnector("alfresco", userName, ServletUtil.getSession());
                                Response res = connector.call("/api/sites/" + currentSite + "/memberships/" + URLEncoder.encode(context.getUserId()));
                                if (res.getStatus().getCode() == 200) {
                                    String response = res.getResponse();
                                    JSONParser p = new JSONParser();
                                    Object o2 = p.parse(response);
                                    if (o2 instanceof org.json.simple.JSONObject) {
                                        org.json.simple.JSONObject jsonRes = (org.json.simple.JSONObject)o2;
                                        String siteMembership = (String)jsonRes.get("role");
                                        isMemberOfCurrentGroup = siteMembership.equals(groupName);
                                    }
                                } else {
                                    isMemberOfCurrentGroup = false;
                                }
                            }
                        } catch (ConnectorServiceException var25) {
                            var25.printStackTrace();
                        } catch (ParseException var26) {
                            var26.printStackTrace();
                        }
                    }
                } else if (groupsList != null) {
                    Iterator i = groupsList.iterator();

                    while(i.hasNext()) {
                        org.json.simple.JSONObject group = (org.json.simple.JSONObject)i.next();
                        userName = group.get("itemName").toString();
                        if (userName.equals(groupName)) {
                            isMemberOfCurrentGroup = true;
                            break;
                        }
                    }
                }
            }

            if (memberOfAllGroups) {
                isMember = isMember == null ? isMemberOfCurrentGroup : isMember && isMemberOfCurrentGroup;
                if (!isMember) {
                    break;
                }
            } else {
                isMember = isMember == null ? isMemberOfCurrentGroup : isMember || isMemberOfCurrentGroup;
                if (isMember) {
                    break;
                }
            }
        }

        return isMember;
    }

    public List<String> getGroups(String groupsParm) {
        List<String> groups = new ArrayList();
        if (groupsParm != null) {
            String[] groupsArr = groupsParm.split(",");
            String[] var4 = groupsArr;
            int var5 = groupsArr.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                String group = var4[var6];
                groups.add(group.trim());
            }
        }

        return groups;
    }

    protected String getHeader(String name) {
        String header = null;
        if (name != null) {
            RequestContext rc = ThreadLocalRequestContext.getRequestContext();
            header = rc.getHeader(name);
        }

        return header;
    }
}
