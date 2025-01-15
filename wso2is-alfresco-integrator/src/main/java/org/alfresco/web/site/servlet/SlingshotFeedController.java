//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.alfresco.error.AlfrescoRuntimeException;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.mvc.FeedController;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;

public class SlingshotFeedController extends FeedController {
    public static final String ENDPOINT_ALFRESCO_FEED = "alfresco-feed";
    private RemoteConfigElement config;
    private ConfigService configService;

    public SlingshotFeedController() {
    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

    protected ModelAndView handleRequestInternal(HttpServletRequest req, HttpServletResponse res) {
        RemoteConfigElement.EndpointDescriptor descriptor = this.getRemoteConfig().getEndpointDescriptor("alfresco-feed");
        if (!descriptor.getExternalAuth()) {
            return super.handleRequestInternal(req, res);
        } else {
            String uri = (String)req.getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
            uri = uri + (req.getQueryString() != null ? "?" + req.getQueryString() : "");

            try {
                req.getRequestDispatcher("/page/" + uri).forward(req, res);
                return null;
            } catch (Throwable var6) {
                throw new AlfrescoRuntimeException(var6.getMessage(), var6);
            }
        }
    }

    private RemoteConfigElement getRemoteConfig() {
        if (this.config == null) {
            this.config = (RemoteConfigElement)this.configService.getConfig("Remote").getConfigElement("remote");
        }

        return this.config;
    }
}
