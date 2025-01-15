//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.packaging;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.VersionNumber;
import org.alfresco.web.scripts.ShareManifest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ModulePackageHelper {
    private static Log logger = LogFactory.getLog(ModulePackageHelper.class);
    private static PropertyDescriptor[] descriptors;
    protected static final String REGEX_NUMBER_OR_DOT = "[0-9\\.]*";
    public static final String MANIFEST_SHARE = "Alfresco Share";

    public ModulePackageHelper() {
    }

    public static Map<String, String> toMap(ModulePackage modulePackage) {
        Map asMap = new HashMap(descriptors.length);

        for(int i = 0; i < descriptors.length; ++i) {
            try {
                String propValue = String.valueOf(descriptors[i].getReadMethod().invoke(modulePackage));
                asMap.put(descriptors[i].getName(), propValue);
            } catch (IllegalAccessException var4) {
                logger.error("Unable to turn ModulePackageUsingProperties into a Map ", var4);
            } catch (InvocationTargetException var5) {
                logger.error("Unable to turn ModulePackageUsingProperties into a Map ", var5);
            }
        }

        return asMap;
    }

    public static void checkValid(ModulePackage module, ShareManifest shareManifest) {
        checkVersions(new VersionNumber(shareManifest.getSpecificationVersion()), module);
    }

    protected static List<String> toIds(List<ModulePackage> mods) {
        List<String> ids = new ArrayList(mods.size());
        Iterator var2 = mods.iterator();

        while(var2.hasNext()) {
            ModulePackage mod = (ModulePackage)var2.next();
            ids.add(mod.getId());
        }

        return ids;
    }

    protected static void checkVersions(VersionNumber warVersion, ModulePackage installingModuleDetails) {
        String var10002;
        if (warVersion.compareTo(installingModuleDetails.getVersionMin()) == -1) {
            var10002 = installingModuleDetails.getTitle();
            throw new AlfrescoRuntimeException("The module (" + var10002 + ") must be installed on a Share version equal to or greater than " + installingModuleDetails.getVersionMin() + ". Share is version: " + warVersion + ".");
        } else if (warVersion.compareTo(installingModuleDetails.getVersionMax()) == 1) {
            var10002 = installingModuleDetails.getTitle();
            throw new AlfrescoRuntimeException("The module (" + var10002 + ") cannot be installed on a Share version greater than " + installingModuleDetails.getVersionMax() + ". Share is version: " + warVersion + ".");
        }
    }

    protected static void checkDependencies(ModulePackage module, List<ModulePackage> availableModules) {
        List<ModulePackageDependency> dependencies = module.getDependencies();
        if (dependencies != null && !dependencies.isEmpty()) {
            List<String> moduleIds = toIds(availableModules);
            List<ModulePackageDependency> missingDependencies = new ArrayList(0);
            Iterator var5 = dependencies.iterator();

            while(var5.hasNext()) {
                ModulePackageDependency dependency = (ModulePackageDependency)var5.next();
                if (!moduleIds.contains(dependency.getId())) {
                    missingDependencies.add(dependency);
                }
            }

            if (!missingDependencies.isEmpty()) {
                String var10002 = module.getTitle();
                throw new AlfrescoRuntimeException("The module (" + var10002 + ") cannot be installed. The following modules must first be installed: " + missingDependencies);
            }
        }

    }

    static {
        try {
            BeanInfo moduleinfo = Introspector.getBeanInfo(ModulePackage.class);
            descriptors = moduleinfo.getPropertyDescriptors();
        } catch (IntrospectionException var1) {
            logger.error("Unable to read bean info for ModulePackage");
        }

    }
}
