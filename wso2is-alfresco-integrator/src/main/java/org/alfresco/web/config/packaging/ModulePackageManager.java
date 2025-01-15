//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.packaging;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.alfresco.web.scripts.ShareManifest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.util.Assert;

public class ModulePackageManager implements InitializingBean {
    public static final String MODULE_RESOURCES = "classpath*:alfresco/module/*/module.properties";
    private static Log logger = LogFactory.getLog(ModulePackageManager.class);
    private ShareManifest shareManifest;
    private List<ModulePackage> modules = new ArrayList();

    public ModulePackageManager() {
    }

    protected List<ModulePackage> resolveModules(String resourcePath) {
        Assert.notNull(resourcePath, "Resource path must not be null");
        ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        List<ModulePackage> modulesFound = new ArrayList();

        try {
            Resource[] resources = resolver.getResources(resourcePath);
            Resource[] var5 = resources;
            int var6 = resources.length;

            for(int var7 = 0; var7 < var6; ++var7) {
                Resource resource = var5[var7];
                ModulePackage mp = asModulePackage(resource);
                if (mp != null) {
                    modulesFound.add(mp);
                }
            }
        } catch (IOException var10) {
            logger.error("Unable to resolve modules ", var10);
        }

        return modulesFound;
    }

    protected static ModulePackage asModulePackage(Resource resource) {
        Assert.notNull(resource, "Resource must not be null");

        try {
            return ModulePackageUsingProperties.loadFromResource(resource);
        } catch (IOException var2) {
            logger.error("Failed to load resource " + resource.toString(), var2);
            return null;
        }
    }

    protected String writeModuleList(List<ModulePackage> foundModules) {
        StringBuilder b = new StringBuilder(128);
        Iterator var3 = foundModules.iterator();

        while(var3.hasNext()) {
            ModulePackage module = (ModulePackage)var3.next();
            b.append(module.getTitle()).append(", " + module.getVersion()).append(", " + module.getDescription());
            b.append("\n");
        }

        return b.toString();
    }

    public List<ModulePackage> getModulePackages() {
        return this.modules;
    }

    public void afterPropertiesSet() {
        logger.debug("Resolving module packages.");
        this.modules = this.resolveModules("classpath*:alfresco/module/*/module.properties");
        String moduleList = this.writeModuleList(this.modules);
        if (!this.modules.isEmpty()) {
            logger.info("Found " + this.modules.size() + " module package(s)");
            logger.info(moduleList);
            Iterator var2 = this.modules.iterator();

            while(var2.hasNext()) {
                ModulePackage module = (ModulePackage)var2.next();
                ModulePackageHelper.checkValid(module, this.shareManifest);
                ModulePackageHelper.checkDependencies(module, this.modules);
            }
        }

    }

    public void setShareManifest(ShareManifest shareManifest) {
        this.shareManifest = shareManifest;
    }
}
