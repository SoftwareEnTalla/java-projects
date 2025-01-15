//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.config.WebFrameworkConfigElement;
import org.springframework.extensions.surf.ModelObjectService;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.TemplatesContainer;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.surf.exception.PlatformRuntimeException;
import org.springframework.extensions.surf.mvc.PageView;
import org.springframework.extensions.surf.render.RenderService;
import org.springframework.extensions.surf.resource.ResourceService;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.types.Page;
import org.springframework.extensions.surf.types.Theme;
import org.springframework.extensions.webscripts.connector.User;

public class SlingshotPageView extends PageView {
    public static final String REDIRECT_URI = "_redirectURI";
    public static final String REDIRECT_QUERY = "_redirectQueryString";
    private RemoteConfigElement config;

    public SlingshotPageView(WebFrameworkConfigElement webFrameworkConfiguration, ModelObjectService modelObjectService, ResourceService resourceService, RenderService renderService, TemplatesContainer templatesContainer) {
        super(webFrameworkConfiguration, modelObjectService, resourceService, renderService, templatesContainer);
    }

    protected void prepareResponse(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-cache");
    }

    protected void validateRequestContext(RequestContext rc, HttpServletRequest req) throws Exception {
        super.validateRequestContext(rc, req);
        String themeId = null;
        String siteId = (String)rc.getUriTokens().get("site");
        if (siteId != null) {
            Page dashboard = this.getObjectService().getPage("site/" + siteId + "/dashboard");
            if (dashboard != null) {
                themeId = dashboard.getProperty("theme");
            }
        } else {
            themeId = rc.getPage().getProperty("theme");
        }

        if (themeId != null && themeId.length() != 0 && !rc.getThemeId().equals(themeId)) {
            Theme theme = this.getObjectService().getTheme(themeId);
            if (theme != null) {
                rc.setTheme(theme);
            }
        }

    }

    protected boolean loginRequiredForPage(RequestContext context, HttpServletRequest request, Page page) {
        boolean externalAuth = false;
        RemoteConfigElement.EndpointDescriptor descriptor = this.getRemoteConfig(context).getEndpointDescriptor("alfresco");
        if (descriptor != null) {
            externalAuth = descriptor.getExternalAuth();
        }

        boolean login = false;
        User user = context.getUser();
        switch (page.getAuthentication()) {
            case guest:
                login = user == null;
                break;
            case user:
                try {
                    login = user == null || AuthenticationUtil.isGuest(user.getId()) || !context.getServiceRegistry().getConnectorService().getCredentialVault(request.getSession(), user.getId()).hasCredentials("alfresco") && !externalAuth;
                    break;
                } catch (CredentialVaultProviderException var10) {
                    throw new PlatformRuntimeException("Unable to retrieve credentials for current user.", var10);
                }
            case admin:
                try {
                    login = user == null || !user.isAdmin() || !context.getServiceRegistry().getConnectorService().getCredentialVault(request.getSession(), user.getId()).hasCredentials("alfresco") && !externalAuth;
                } catch (CredentialVaultProviderException var9) {
                    throw new PlatformRuntimeException("Unable to retrieve credentials for current user.", var9);
                }

                if (login) {
                    if (!user.isGuest()) {
                        throw new PlatformRuntimeException("Non-admin user tries to access a page that requires admin privilege.");
                    }

                    AuthenticationUtil.clearUserContext(request);
                }
        }

        return login;
    }

    protected String buildLoginRedirectURL(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute("_redirectURI") != null) {
            Object var10000 = session.getAttribute("_redirectURI");
            String redirectUrl = "" + var10000 + (session.getAttribute("_redirectQueryString") != null ? "?" + session.getAttribute("_redirectQueryString") : "");
            session.removeAttribute("_redirectURI");
            session.removeAttribute("_redirectQueryString");
            return redirectUrl;
        } else {
            return super.buildLoginRedirectURL(request);
        }
    }

    private RemoteConfigElement getRemoteConfig(RequestContext context) {
        if (this.config == null) {
            this.config = (RemoteConfigElement)context.getServiceRegistry().getConfigService().getConfig("Remote").getConfigElement("remote");
        }

        return this.config;
    }
}
