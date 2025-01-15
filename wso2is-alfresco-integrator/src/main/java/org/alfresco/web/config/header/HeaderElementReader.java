//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.header;

import java.util.Iterator;
import java.util.List;
import org.alfresco.web.config.forms.DependenciesConfigElement;
import org.alfresco.web.config.forms.DependenciesElementReader;
import org.dom4j.Element;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

public class HeaderElementReader implements ConfigElementReader {
    public static final String ELEMENT_HEADER = "header";

    public HeaderElementReader() {
    }

    public ConfigElement parse(Element headerElement) {
        HeaderConfigElement result = null;
        if (headerElement == null) {
            return null;
        } else {
            String name = headerElement.getName();
            if (!name.equals("header")) {
                String var10002 = this.getClass().getName();
                throw new ConfigException(var10002 + " can only parse header elements, the element passed was '" + name + "'");
            } else {
                result = new HeaderConfigElement();
                boolean configuredLegacyMode = true;
                List<Element> legacyModeElements = headerElement.elements("legacy-mode-enabled");

                Element maxDisplayedSitePagesEl;
                for(Iterator var6 = legacyModeElements.iterator(); var6.hasNext(); configuredLegacyMode = configuredLegacyMode && Boolean.parseBoolean(maxDisplayedSitePagesEl.getStringValue())) {
                    maxDisplayedSitePagesEl = (Element)var6.next();
                }

                result.setLegacyMode(configuredLegacyMode && legacyModeElements.size() > 0);
                Element maxRecentSitesEl = headerElement.element("max-recent-sites");
                if (maxRecentSitesEl != null) {
                    maxDisplayedSitePagesEl = null;
                    Integer maxRecentSites = Integer.parseInt(maxRecentSitesEl.getStringValue());
                    result.setMaxRecentSites(maxRecentSites);
                }

                maxDisplayedSitePagesEl = headerElement.element("max-displayed-site-pages");
                if (maxDisplayedSitePagesEl != null) {
                    Integer maxDisplayedSitePages = null;
                    maxDisplayedSitePages = Integer.parseInt(maxDisplayedSitePagesEl.getStringValue());
                    result.setMaxDisplayedSitePages(maxDisplayedSitePages);
                }

                Iterator var15 = headerElement.selectNodes("./app-items").iterator();

                Object obj;
                Element depsElement;
                HeaderItemsElementReader userReader;
                HeaderItemsConfigElement userCE;
                while(var15.hasNext()) {
                    obj = var15.next();
                    depsElement = (Element)obj;
                    userReader = new HeaderItemsElementReader();
                    userCE = (HeaderItemsConfigElement)userReader.parse(depsElement);
                    result.setAppItems(userCE);
                }

                var15 = headerElement.selectNodes("./user-items").iterator();

                while(var15.hasNext()) {
                    obj = var15.next();
                    depsElement = (Element)obj;
                    userReader = new HeaderItemsElementReader();
                    userCE = (HeaderItemsConfigElement)userReader.parse(depsElement);
                    result.setUserItems(userCE);
                }

                var15 = headerElement.selectNodes("./dependencies").iterator();

                while(var15.hasNext()) {
                    obj = var15.next();
                    depsElement = (Element)obj;
                    DependenciesElementReader depsReader = new DependenciesElementReader();
                    DependenciesConfigElement depsCE = (DependenciesConfigElement)depsReader.parse(depsElement);
                    result.setDependencies(depsCE);
                }

                return result;
            }
        }
    }
}
