//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.packaging;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.alfresco.util.VersionNumber;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.VersionRange;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

public class ModulePackageUsingProperties implements ModulePackage {
    public static final String PROP_ID = "module.id";
    public static final String PROP_VERSION = "module.version";
    public static final String PROP_TITLE = "module.title";
    public static final String PROP_DESCRIPTION = "module.description";
    public static final String PROP_EDITIONS = "module.editions";
    public static final String PROP_REPO_VERSION_MIN = "module.repo.version.min";
    public static final String PROP_REPO_VERSION_MAX = "module.repo.version.max";
    public static final String PROP_DEPENDS_PREFIX = "module.depends.";
    public static final String PROP_SHARE_VERSION_MIN = "module.share.version.min";
    public static final String PROP_SHARE_VERSION_MAX = "module.share.version.max";
    private final Properties properties;
    private final List<ModulePackageDependency> dependencies = new ArrayList();

    protected ModulePackageUsingProperties(Properties properties) {
        this.validateProperties(properties);
        this.properties = properties;
    }

    public static ModulePackageUsingProperties loadFromResource(Resource resource) throws IOException {
        Properties props = new Properties();
        props.load(resource.getInputStream());
        return new ModulePackageUsingProperties(props);
    }

    protected void validateProperties(Properties props) {
        if (!props.containsKey("module.share.version.min") && props.containsKey("module.repo.version.min")) {
            props.setProperty("module.share.version.min", props.getProperty("module.repo.version.min"));
        }

        if (!props.containsKey("module.share.version.max") && props.containsKey("module.repo.version.max")) {
            props.setProperty("module.share.version.max", props.getProperty("module.repo.version.max"));
        }

        this.dependencies.addAll(extractDependencies(props));
    }

    public String getId() {
        return this.properties.getProperty("module.id");
    }

    public String getTitle() {
        return this.properties.getProperty("module.title");
    }

    public String getDescription() {
        return this.properties.getProperty("module.description");
    }

    public ArtifactVersion getVersion() {
        String ver = this.properties.getProperty("module.version");
        return StringUtils.isEmpty(ver) ? new DefaultArtifactVersion("0-ERROR_UNSET") : new DefaultArtifactVersion(ver);
    }

    public VersionNumber getVersionMin() {
        String ver = this.properties.getProperty("module.share.version.min");
        return StringUtils.isEmpty(ver) ? VersionNumber.VERSION_ZERO : new VersionNumber(ver);
    }

    public VersionNumber getVersionMax() {
        String ver = this.properties.getProperty("module.share.version.max");
        return StringUtils.isEmpty(ver) ? VersionNumber.VERSION_BIG : new VersionNumber(ver);
    }

    public List<ModulePackageDependency> getDependencies() {
        return this.dependencies;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("ModulePackageUsingProperties{");
        sb.append("id='").append(this.getId()).append('\'');
        sb.append(", title='").append(this.getTitle()).append('\'');
        sb.append(", description='").append(this.getDescription()).append('\'');
        sb.append(", version=").append(this.getVersion());
        sb.append(", versionMin=").append(this.getVersionMin());
        sb.append(", versionMax=").append(this.getVersionMax());
        sb.append(", dependencies=").append(this.dependencies);
        sb.append('}');
        return sb.toString();
    }

    private static List<ModulePackageDependency> extractDependencies(Properties properties) {
        int prefixLength = "module.depends.".length();
        List<ModulePackageDependency> dependencies = new ArrayList(2);
        Iterator var3 = properties.entrySet().iterator();

        while(var3.hasNext()) {
            Map.Entry entry = (Map.Entry)var3.next();
            String key = (String)entry.getKey();
            String value = (String)entry.getValue();
            if (key.startsWith("module.depends.") && key.length() != prefixLength) {
                String dependencyId = key.substring(prefixLength);
                ModulePackageDependency dependency = new ModulePackageDependencyOnlyId(dependencyId);
                dependencies.add(dependency);
            }
        }

        return dependencies;
    }

    public static class ModulePackageDependencyOnlyId implements ModulePackageDependency {
        String id;

        public ModulePackageDependencyOnlyId(String dependencyId) {
            this.id = dependencyId;
        }

        public String getId() {
            return this.id;
        }

        public VersionRange getVersionRange() {
            return null;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder("");
            sb.append("id='").append(this.id).append('\'');
            return sb.toString();
        }
    }
}
