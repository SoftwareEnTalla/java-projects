//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.alfresco.web.site.servlet.MTAuthenticationFilter;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.exception.PlatformRuntimeException;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.extensions.surf.mvc.PageView;
import org.springframework.extensions.surf.mvc.PageViewResolver;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.types.Page;
import org.springframework.web.servlet.view.AbstractUrlBasedView;

public class SlingshotPageViewResolver extends PageViewResolver {
    protected static final String URI_SITE = "site";
    protected static final String URI_PAGEID = "pageid";
    protected static final Pattern REGEX_PATTERN_SITE_ROOT = Pattern.compile("site\\/((\\w|-)+)\\/?$");
    protected static final String PAGE_ID_SITE_ROOT = "site-redirect";

    public SlingshotPageViewResolver() {
    }

    protected Page lookupPage(String pageId) {
        if (ThreadLocalRequestContext.getRequestContext().getUser() == null) {
            HttpServletRequest req = MTAuthenticationFilter.getCurrentServletRequest();
            if (req != null) {
                try {
                    RequestContextUtil.initRequestContext(this.getApplicationContext(), req);
                } catch (RequestContextException var4) {
                    throw new PlatformRuntimeException("Failed to init Request Context: " + var4.getMessage(), var4);
                }
            }
        }

        Page page = ThreadLocalRequestContext.getRequestContext().getPage();
        return page != null ? page : super.lookupPage(pageId);
    }

    protected AbstractUrlBasedView buildView(String viewName) {
        PageView view = null;
        Page page = ThreadLocalRequestContext.getRequestContext().getPage();
        if (page != null) {
            view = new SlingshotPageView(this.getWebframeworkConfigElement(), this.getModelObjectService(), this.getWebFrameworkResourceService(), this.getWebFrameworkRenderService(), this.getTemplatesContainer());
            view.setUrl(viewName);
            view.setPage(page);
            view.setUriTokens(ThreadLocalRequestContext.getRequestContext().getUriTokens());
            view.setUrlHelperFactory(this.getUrlHelperFactory());
        }

        return view;
    }

    protected Map<String, String> getTokens(String viewName) {
        Matcher matcher = REGEX_PATTERN_SITE_ROOT.matcher(viewName);
        if (matcher.matches()) {
            Map<String, String> tokens = new HashMap(4);
            tokens.put("site", matcher.group(1));
            tokens.put("pageid", "site-redirect");
            return tokens;
        } else {
            return super.getTokens(viewName);
        }
    }
}
