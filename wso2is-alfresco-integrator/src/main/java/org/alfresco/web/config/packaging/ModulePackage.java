//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.packaging;

import java.util.List;
import org.alfresco.util.VersionNumber;
import org.apache.maven.artifact.versioning.ArtifactVersion;

public interface ModulePackage {
    String UNSET_VERSION = "0-ERROR_UNSET";

    String getId();

    ArtifactVersion getVersion();

    String getTitle();

    String getDescription();

    VersionNumber getVersionMin();

    VersionNumber getVersionMax();

    List<ModulePackageDependency> getDependencies();
}
