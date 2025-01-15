//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.webscripts.servlet.mvc.ProxyControllerInterceptor;

public class SlingshotProxyControllerInterceptor implements ProxyControllerInterceptor {
    public SlingshotProxyControllerInterceptor() {
    }

    public boolean allowHttpBasicAuthentication(RemoteConfigElement.EndpointDescriptor endpoint, String uri) {
        return uri.contains("/wso2/") || uri.contains("/api/node/content") || uri.contains("/cmis/") && uri.contains("/content");
    }

    public boolean exceptionOnError(RemoteConfigElement.EndpointDescriptor endpoint, String uri) {
        return this.allowHttpBasicAuthentication(endpoint, uri);
    }
}
