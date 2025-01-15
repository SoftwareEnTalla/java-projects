//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.portlet;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.context.ApplicationContext;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.WebFrameworkServiceRegistry;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.util.URLDecoder;
import org.springframework.web.context.support.WebApplicationContextUtils;

public class LazyDashboardFilter implements Filter {
    private static final Pattern PATTERN_DASHBOARD_PATH = Pattern.compile("/user/([^/]*)/dashboard");
    private ServletContext servletContext;

    public LazyDashboardFilter() {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        String pathInfo = httpServletRequest.getPathInfo();
        Matcher matcher;
        if (pathInfo != null && (matcher = PATTERN_DASHBOARD_PATH.matcher(pathInfo)).matches()) {
            RequestContext context;
            try {
                context = RequestContextUtil.initRequestContext(this.getApplicationContext(), (HttpServletRequest)request);
            } catch (RequestContextException var11) {
                throw new ServletException(var11);
            }

            String userid = context.getUserId();
            if (userid != null && userid.equals(URLDecoder.decode(matcher.group(1)))) {
                WebFrameworkServiceRegistry serviceRegistry = context.getServiceRegistry();
                if (serviceRegistry.getModelObjectService().getPage("user/" + userid + "/dashboard") == null) {
                    Map<String, String> tokens = new HashMap();
                    tokens.put("userid", userid);
                    serviceRegistry.getPresetsManager().constructPreset("user-dashboard", tokens);
                }
            }
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig config) throws ServletException {
        this.servletContext = config.getServletContext();
    }

    public void destroy() {
    }

    private ApplicationContext getApplicationContext() {
        return WebApplicationContextUtils.getWebApplicationContext(this.servletContext);
    }
}
