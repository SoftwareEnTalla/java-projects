//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.dom4j.Attribute;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

public class DependenciesElementReader implements ConfigElementReader {
    public static final String ELEMENT_DEPENDENCIES = "dependencies";

    public DependenciesElementReader() {
    }

    public ConfigElement parse(Element dependenciesElem) {
        DependenciesConfigElement result = null;
        if (dependenciesElem == null) {
            return null;
        } else {
            String name = dependenciesElem.getName();
            if (!name.equals("dependencies")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse dependencies elements, the element passed was '" + name + "'");
            } else {
                result = new DependenciesConfigElement();
                List<String> cssDependencies = this.getSrcDependencies(dependenciesElem, "./css");
                List<String> jsDependencies = this.getSrcDependencies(dependenciesElem, "./js");
                result.addCssDependencies(cssDependencies);
                result.addJsDependencies(jsDependencies);
                return result;
            }
        }
    }

    private List<String> getSrcDependencies(Element typeNode, String xpathExpression) {
        List<String> result = new ArrayList();
        Iterator var4 = typeNode.selectNodes(xpathExpression).iterator();

        while(var4.hasNext()) {
            Object cssObj = var4.next();
            Element cssElem = (Element)cssObj;
            List<Attribute> cssAttributes = new ArrayList();
            Iterator var8 = cssElem.selectNodes("./@*").iterator();

            while(var8.hasNext()) {
                Object obj = var8.next();
                cssAttributes.add((Attribute)obj);
            }

            var8 = cssAttributes.iterator();

            while(var8.hasNext()) {
                Attribute nextAttr = (Attribute)var8.next();
                String nextAttrName = nextAttr.getName();
                if (nextAttrName.equals("src")) {
                    String nextAttrValue = nextAttr.getValue();
                    result.add(nextAttrValue);
                }
            }
        }

        return result;
    }
}
