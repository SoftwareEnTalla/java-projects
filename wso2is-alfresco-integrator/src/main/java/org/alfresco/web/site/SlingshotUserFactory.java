//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import org.alfresco.web.site.servlet.SlingshotLoginController;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.site.AlfrescoUser;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.AlfrescoUserFactory;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.User;
import org.springframework.extensions.webscripts.json.JSONWriter;

public class SlingshotUserFactory extends AlfrescoUserFactory {
    public static final String ALF_USER_LOADED = "alfUserLoaded";
    public static final String ALF_USER_GROUPS = "alfUserGroups";
    public static final String CM_USERSTATUS = "{http://www.alfresco.org/model/content/1.0}userStatus";
    public static final String CM_USERSTATUSTIME = "{http://www.alfresco.org/model/content/1.0}userStatusTime";
    public static final String CM_USERHOME = "{http://www.alfresco.org/model/content/1.0}homeFolder";
    public static final String PROP_USERSTATUS = "userStatus";
    public static final String PROP_USERSTATUSTIME = "userStatusTime";
    public static final String PROP_USERHOME = "userHome";
    public static final String CM_PREFERENCEVALUES = "{http://www.alfresco.org/model/content/1.0}preferenceValues";
    public static final String PROP_USERHOMEPAGE = "userHomePage";
    public static final String PREFERENCE_USERHOMEPAGE = "org.alfresco.share.user.homePage";
    public static final String ACTIVITI_ADMIN_ENDPOINT_ID = "activiti-admin";

    public SlingshotUserFactory() {
    }

    public boolean authenticate(HttpServletRequest request, String username, String password) {
        boolean authenticated = false;
        if (!AuthenticationUtil.isGuest(username)) {
            authenticated = super.authenticate(request, username, password);
            if (authenticated) {
                CredentialVault vault = this.frameworkUtils.getCredentialVault(request.getSession(), username);
                Credentials credentials = vault.newCredentials("activiti-admin");
                credentials.setProperty("cleartextUsername", username);
                credentials.setProperty("cleartextPassword", password);
            }
        }

        return authenticated;
    }

    protected AlfrescoUser constructUser(JSONObject properties, Map<String, Boolean> capabilities, Map<String, Boolean> immutability) throws JSONException {
        AlfrescoUser user = new SlingshotUser(properties.getString("{http://www.alfresco.org/model/content/1.0}userName"), capabilities, immutability);
        user.setProperty("userStatus", properties.has("{http://www.alfresco.org/model/content/1.0}userStatus") ? properties.getString("{http://www.alfresco.org/model/content/1.0}userStatus") : null);
        user.setProperty("userStatusTime", properties.has("{http://www.alfresco.org/model/content/1.0}userStatusTime") ? properties.getString("{http://www.alfresco.org/model/content/1.0}userStatusTime") : null);
        user.setProperty("userHome", properties.has("{http://www.alfresco.org/model/content/1.0}homeFolder") ? properties.getString("{http://www.alfresco.org/model/content/1.0}homeFolder") : null);
        if (properties.has("{http://www.alfresco.org/model/content/1.0}preferenceValues")) {
            String preferenceValues = properties.getString("{http://www.alfresco.org/model/content/1.0}preferenceValues");
            if (preferenceValues.trim().length() != 0) {
                try {
                    JSONObject preferences = new JSONObject(preferenceValues);
                    String defaultPage = preferences.getString("org.alfresco.share.user.homePage");
                    if (defaultPage != null && !defaultPage.trim().equals("")) {
                        user.setProperty("userHomePage", defaultPage);
                    }
                } catch (JSONException var8) {
                }
            }
        }

        return user;
    }

    public User loadUser(RequestContext context, String userId, String endpointId) throws UserFactoryException {
        User user = super.loadUser(context, userId, endpointId);
        user.setProperty("alfUserLoaded", (new Date()).getTime());
        HttpSession session = ServletUtil.getSession(false);
        if (session != null) {
            String groups = (String)session.getAttribute(SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS);
            if (groups != null) {
                user.setProperty("alfUserGroups", groups);
            }
        }

        return user;
    }

    public String getUserHomePage(RequestContext context, String userId) throws UserFactoryException {
        String homePage = "/page/user/" + URLEncoder.encode(userId) + "/dashboard";
        User user = context.getUser();
        if (user != null) {
            String userHomePage = (String)user.getProperty("userHomePage");
            if (userHomePage != null && !userHomePage.trim().equals("")) {
                homePage = userHomePage;
            }
        }

        return homePage;
    }

    public void saveUser(AlfrescoUser user) throws UserFactoryException {
        RequestContext context = ThreadLocalRequestContext.getRequestContext();
        if (!context.getUserId().equals(user.getId())) {
            throw new UserFactoryException("Unable to persist user with different Id that current Id.");
        } else {
            StringBuilderWriter buf = new StringBuilderWriter(512);
            JSONWriter writer = new JSONWriter(buf);

            try {
                writer.startObject();
                writer.writeValue("username", user.getId());
                writer.startValue("properties");
                writer.startObject();
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}firstName", user.getFirstName());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}lastName", user.getLastName());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}jobtitle", user.getJobTitle());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}organization", user.getOrganization());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}location", user.getLocation());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}email", user.getEmail());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}telephone", user.getTelephone());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}mobile", user.getMobilePhone());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}skype", user.getSkype());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}instantmsg", user.getInstantMsg());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}googleusername", user.getGoogleUsername());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companyaddress1", user.getCompanyAddress1());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companyaddress2", user.getCompanyAddress2());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companyaddress3", user.getCompanyAddress3());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companypostcode", user.getCompanyPostcode());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companyfax", user.getCompanyFax());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companyemail", user.getCompanyEmail());
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}companytelephone", user.getCompanyTelephone());
                writer.endObject();
                writer.endValue();
                writer.startValue("content");
                writer.startObject();
                writer.writeValue("{http://www.alfresco.org/model/content/1.0}persondescription", user.getBiography());
                writer.endObject();
                writer.endValue();
                writer.endObject();
                Connector conn = FrameworkUtil.getConnector(context, "alfresco");
                ConnectorContext c = new ConnectorContext(HttpMethod.POST);
                c.setContentType("application/json");
                Response res = conn.call("/slingshot/profile/userprofile", c, new ByteArrayInputStream(buf.toString().getBytes()));
                if (200 != res.getStatus().getCode()) {
                    throw new UserFactoryException("Remote error during User save: " + res.getStatus().getMessage());
                }
            } catch (IOException var8) {
                throw new UserFactoryException("IO error during User save: " + var8.getMessage(), var8);
            } catch (ConnectorServiceException var9) {
                throw new UserFactoryException("Configuration error during User save: " + var9.getMessage(), var9);
            }
        }
    }
}
