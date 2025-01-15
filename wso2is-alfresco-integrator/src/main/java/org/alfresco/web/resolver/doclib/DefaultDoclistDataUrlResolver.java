//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.resolver.doclib;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.springframework.extensions.surf.util.URLEncoder;

public class DefaultDoclistDataUrlResolver implements DoclistDataUrlResolver {
    public String basePath = null;

    public DefaultDoclistDataUrlResolver() {
    }

    public void setBasePath(String basePath) {
        this.basePath = basePath;
    }

    public String resolve(String webscript, String params, HashMap<String, String> args) {
        String var10000 = this.basePath;
        return var10000 + "/" + webscript + "/" + URLEncoder.encodeUri(params) + this.getArgsAsParameters(args);
    }

    public String getArgsAsParameters(HashMap<String, String> args) {
        String urlParameters = "";
        if (args.size() > 0) {
            StringBuilder argsBuf = new StringBuilder(128);
            argsBuf.append('?');

            Map.Entry arg;
            for(Iterator var4 = args.entrySet().iterator(); var4.hasNext(); argsBuf.append((String)arg.getKey()).append('=').append(URLEncoder.encodeUriComponent(((String)arg.getValue()).replaceAll("%25", "%2525")))) {
                arg = (Map.Entry)var4.next();
                if (argsBuf.length() > 1) {
                    argsBuf.append('&');
                }
            }

            urlParameters = argsBuf.toString();
        }

        return urlParameters;
    }
}
