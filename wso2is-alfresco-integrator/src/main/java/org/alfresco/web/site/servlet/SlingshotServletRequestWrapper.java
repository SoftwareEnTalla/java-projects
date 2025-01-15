//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SlingshotServletRequestWrapper extends HttpServletRequestWrapper {
    private Map<String, String> headerMap = new HashMap(8);

    public SlingshotServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    public void addHeader(String name, String value) {
        this.headerMap.put(name, value);
    }

    public String getHeader(String name) {
        String value = (String)this.headerMap.get(name);
        return value != null ? value : ((HttpServletRequest)this.getRequest()).getHeader(name);
    }

    public Enumeration getHeaders(String name) {
        String value = (String)this.headerMap.get(name);
        if (value != null) {
            List<String> values = new ArrayList(8);
            values.add(value);
            return Collections.enumeration(values);
        } else {
            return super.getHeaders(name);
        }
    }

    public Enumeration<String> getHeaderNames() {
        HttpServletRequest request = (HttpServletRequest)this.getRequest();
        List<String> list = new ArrayList(16);
        Enumeration<?> e = request.getHeaderNames();

        while(e.hasMoreElements()) {
            list.add(e.nextElement().toString());
        }

        Iterator var4 = this.headerMap.keySet().iterator();

        while(var4.hasNext()) {
            String key = (String)var4.next();
            list.add(key);
        }

        return Collections.enumeration(list);
    }
}
