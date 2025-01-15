//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class KerberosConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = 4178518406841891833L;
    private String password;
    private String realm;
    private String endpointSPN;
    private String loginEntryName;
    private boolean stripUserNameSuffix = true;

    public KerberosConfigElement() {
        super("kerberos");
    }

    public ConfigElement combine(ConfigElement element) {
        KerberosConfigElement configElement = (KerberosConfigElement)element;
        KerberosConfigElement combinedElement = new KerberosConfigElement();
        combinedElement.password = configElement.password == null ? this.password : configElement.password;
        combinedElement.realm = configElement.realm == null ? this.realm : configElement.realm;
        combinedElement.endpointSPN = configElement.endpointSPN == null ? this.endpointSPN : configElement.endpointSPN;
        combinedElement.loginEntryName = configElement.loginEntryName == null ? this.loginEntryName : configElement.loginEntryName;
        combinedElement.stripUserNameSuffix = configElement.stripUserNameSuffix;
        return combinedElement;
    }

    public String getPassword() {
        return this.password;
    }

    public String getRealm() {
        return this.realm;
    }

    public String getEndpointSPN() {
        return this.endpointSPN;
    }

    public String getLoginEntryName() {
        return this.loginEntryName == null ? "ShareHTTP" : this.loginEntryName;
    }

    public boolean getStripUserNameSuffix() {
        return this.stripUserNameSuffix;
    }

    protected static KerberosConfigElement newInstance(Element elem) {
        KerberosConfigElement configElement = new KerberosConfigElement();
        String password = elem.elementTextTrim("password");
        if (password != null && password.length() > 0) {
            configElement.password = password;
        }

        String realm = elem.elementTextTrim("realm");
        if (realm != null && realm.length() > 0) {
            configElement.realm = realm;
        }

        String endpointSPN = elem.elementTextTrim("endpoint-spn");
        if (endpointSPN != null && endpointSPN.length() > 0) {
            configElement.endpointSPN = endpointSPN;
        }

        String loginEntryName = elem.elementTextTrim("config-entry");
        if (loginEntryName != null && loginEntryName.length() > 0) {
            configElement.loginEntryName = loginEntryName;
        }

        String stripUserNameSuffix = elem.elementTextTrim("stripUserNameSuffix");
        if (stripUserNameSuffix != null && stripUserNameSuffix.length() > 0) {
            configElement.stripUserNameSuffix = Boolean.parseBoolean(stripUserNameSuffix);
        }

        return configElement;
    }
}
