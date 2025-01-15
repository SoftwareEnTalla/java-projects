//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import java.util.Iterator;
import org.alfresco.encryptor.PublicPrivateKeyShareStringEncryptor;
import org.dom4j.Attribute;
import org.dom4j.Element;
import org.jasypt.properties.PropertyValueEncryptionUtils;

public class AlfrescoEncryptionElementConvert {
    private final PublicPrivateKeyShareStringEncryptor stringEncryptor;

    public AlfrescoEncryptionElementConvert() {
        this.stringEncryptor = new PublicPrivateKeyShareStringEncryptor();
        this.stringEncryptor.init();
    }

    public AlfrescoEncryptionElementConvert(PublicPrivateKeyShareStringEncryptor stringEncryptor) {
        this.stringEncryptor = stringEncryptor;
    }

    public void parse(Element element) {
        if (element != null) {
            this.convertElement(element);
            this.processChildren(element);
        }

    }

    protected void processChildren(Element element) {
        Iterator<Element> children = element.elementIterator();

        while(children.hasNext()) {
            Element child = (Element)children.next();
            this.convertElement(child);
            this.processChildren(child);
        }

    }

    protected void convertElement(Element element) {
        if (element.hasContent() && !element.hasMixedContent()) {
            String value = element.getTextTrim();
            if (value != null && value.length() > 0) {
                value = this.convertElementValue(value);
                element.setText(value);
            }
        }

        Iterator<Attribute> attrs = element.attributeIterator();

        while(attrs.hasNext()) {
            Attribute attr = (Attribute)attrs.next();
            String attrName = attr.getName();
            String attrValue = attr.getValue();
            attrValue = this.convertElementValue(attrValue);
            element.addAttribute(attrName, attrValue);
        }

    }

    protected String convertElementValue(String originalValue) {
        if (!PropertyValueEncryptionUtils.isEncryptedValue(originalValue)) {
            return originalValue;
        } else {
            return this.stringEncryptor != null ? PropertyValueEncryptionUtils.decrypt(originalValue, this.stringEncryptor) : null;
        }
    }
}
