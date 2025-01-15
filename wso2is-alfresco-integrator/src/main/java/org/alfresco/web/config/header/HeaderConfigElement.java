//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.header;

import java.util.List;
import org.alfresco.web.config.forms.DependenciesConfigElement;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class HeaderConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = 7721694406825674057L;
    public static final String HEADER_ID = "header";
    private boolean legacyMode = false;
    private int maxRecentSites;
    private int maxDisplayedSitePages;
    private HeaderItemsConfigElement appItemsConfigElement;
    private HeaderItemsConfigElement userItemsConfigElement;
    private DependenciesConfigElement dependenciesConfigElement;

    public HeaderConfigElement() {
        super("header");
    }

    public HeaderConfigElement(String name) {
        super(name);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the header config via the generic interfaces is not supported");
    }

    public boolean getLegacyMode() {
        return this.legacyMode;
    }

    void setLegacyMode(boolean enabled) {
        this.legacyMode = enabled;
    }

    public int getMaxRecentSites() {
        return this.maxRecentSites;
    }

    void setMaxRecentSites(int n) {
        this.maxRecentSites = n;
    }

    public int getMaxDisplayedSitePages() {
        return this.maxDisplayedSitePages;
    }

    void setMaxDisplayedSitePages(int n) {
        this.maxDisplayedSitePages = n;
    }

    public HeaderItemsConfigElement getAppItems() {
        return this.appItemsConfigElement;
    }

    void setAppItems(HeaderItemsConfigElement items) {
        this.appItemsConfigElement = items;
    }

    public HeaderItemsConfigElement getUserItems() {
        return this.userItemsConfigElement;
    }

    void setUserItems(HeaderItemsConfigElement items) {
        this.userItemsConfigElement = items;
    }

    public DependenciesConfigElement getDependencies() {
        return this.dependenciesConfigElement;
    }

    void setDependencies(DependenciesConfigElement dependencies) {
        this.dependenciesConfigElement = dependencies;
    }

    public ConfigElement combine(ConfigElement otherConfigElement) {
        HeaderConfigElement otherHeaderElem = (HeaderConfigElement)otherConfigElement;
        HeaderConfigElement result = new HeaderConfigElement();
        ConfigElement combinedDependencies = this.dependenciesConfigElement == null ? otherHeaderElem.getDependencies() : this.dependenciesConfigElement.combine(otherHeaderElem.getDependencies());
        result.setDependencies((DependenciesConfigElement)combinedDependencies);
        return result;
    }
}
