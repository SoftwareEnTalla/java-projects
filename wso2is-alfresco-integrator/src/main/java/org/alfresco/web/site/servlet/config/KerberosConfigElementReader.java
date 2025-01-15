//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

public class KerberosConfigElementReader implements ConfigElementReader {
    private AlfrescoEncryptionElementConvert elemConverter = new AlfrescoEncryptionElementConvert();

    public KerberosConfigElementReader() {
    }

    public ConfigElement parse(Element elem) {
        ConfigElement configElement = null;
        if (elem != null) {
            this.elemConverter.parse(elem);
            configElement = KerberosConfigElement.newInstance(elem);
        }

        return configElement;
    }
}
