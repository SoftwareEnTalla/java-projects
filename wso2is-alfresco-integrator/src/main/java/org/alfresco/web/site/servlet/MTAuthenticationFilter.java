//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public class MTAuthenticationFilter implements Filter {
    private static ThreadLocal<HttpServletRequest> requestHolder = new ThreadLocal();
    private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";

    public MTAuthenticationFilter() {
    }

    public void init(FilterConfig config) throws ServletException {
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (req instanceof HttpServletRequest) {
            requestHolder.set((HttpServletRequest)req);
            if (((HttpServletRequest)req).getHeader("Accept-Language") == null) {
                req = new SlingshotServletRequestWrapper((HttpServletRequest)req);
                ((SlingshotServletRequestWrapper)req).addHeader("Accept-Language", "en_US");
            }
        }

        try {
            chain.doFilter((ServletRequest)req, res);
        } finally {
            requestHolder.remove();
        }

    }

    public static HttpServletRequest getCurrentServletRequest() {
        return (HttpServletRequest)requestHolder.get();
    }

    public void destroy() {
    }
}
