//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.ArrayList;
import java.util.List;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigException;
import org.springframework.extensions.config.element.ConfigElementAdapter;

public class DependenciesConfigElement extends ConfigElementAdapter {
    private static final long serialVersionUID = -8573715101320883067L;
    public static final String CONFIG_ELEMENT_ID = "dependencies";
    private final List<String> cssDependencies = new ArrayList();
    private final List<String> jsDependencies = new ArrayList();

    public DependenciesConfigElement() {
        super("dependencies");
    }

    public DependenciesConfigElement(String name) {
        super(name);
    }

    public String[] getCss() {
        return this.cssDependencies.isEmpty() ? null : (String[])this.cssDependencies.toArray(new String[0]);
    }

    public String[] getJs() {
        return this.jsDependencies.isEmpty() ? null : (String[])this.jsDependencies.toArray(new String[0]);
    }

    public List<ConfigElement> getChildren() {
        throw new ConfigException("Reading the default-controls config via the generic interfaces is not supported");
    }

    public ConfigElement combine(ConfigElement configElement) {
        if (configElement == null) {
            return this;
        } else {
            DependenciesConfigElement otherDepsElement = (DependenciesConfigElement)configElement;
            DependenciesConfigElement result = new DependenciesConfigElement();
            if (!this.cssDependencies.isEmpty()) {
                result.addCssDependencies(this.cssDependencies);
            }

            if (!otherDepsElement.cssDependencies.isEmpty()) {
                result.addCssDependencies(otherDepsElement.cssDependencies);
            }

            if (!this.jsDependencies.isEmpty()) {
                result.addJsDependencies(this.jsDependencies);
            }

            if (!otherDepsElement.jsDependencies.isEmpty()) {
                result.addJsDependencies(otherDepsElement.jsDependencies);
            }

            return result;
        }
    }

    void addCssDependencies(List<String> cssDeps) {
        if (cssDeps != null) {
            this.cssDependencies.addAll(cssDeps);
        }
    }

    void addJsDependencies(List<String> jsDeps) {
        if (jsDeps != null) {
            this.jsDependencies.addAll(jsDeps);
        }
    }
}
