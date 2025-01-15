//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

class DefaultControlsElementReader implements ConfigElementReader {
    public static final String ELEMENT_DEFAULT_CONTROLS = "default-controls";
    public static final String ELEMENT_CONTROL_PARAM = "control-param";
    public static final String ATTR_NAME = "name";
    public static final String ATTR_TEMPLATE = "template";

    DefaultControlsElementReader() {
    }

    public ConfigElement parse(Element defaultCtrlsElem) {
        DefaultControlsConfigElement result = null;
        if (defaultCtrlsElem == null) {
            return null;
        } else {
            String name = defaultCtrlsElem.getName();
            if (!name.equals("default-controls")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse default-controls elements, the element passed was '" + name + "'");
            } else {
                result = new DefaultControlsConfigElement();
                Iterator<Element> typeNodes = defaultCtrlsElem.elementIterator();

                while(typeNodes.hasNext()) {
                    Element nextTypeNode = (Element)typeNodes.next();
                    String typeName = nextTypeNode.attributeValue("name");
                    String templatePath = nextTypeNode.attributeValue("template");
                    List<Element> controlParamNodes = nextTypeNode.elements("control-param");
                    ControlParam param = null;
                    List<ControlParam> params = new ArrayList();
                    Iterator var11 = controlParamNodes.iterator();

                    while(var11.hasNext()) {
                        Element nextControlParam = (Element)var11.next();
                        String paramName = nextControlParam.attributeValue("name");
                        String elementValue = nextControlParam.getTextTrim();
                        param = new ControlParam(paramName, elementValue);
                        params.add(param);
                    }

                    result.addDataMapping(typeName, templatePath, params);
                }

                return result;
            }
        }
    }
}
