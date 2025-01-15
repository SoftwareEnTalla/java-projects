//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import org.alfresco.error.AlfrescoRuntimeException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.Resource;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public class ShareManifest extends BaseProcessorExtension {
    public static final String MANIFEST_SPECIFICATION_VERSION = "Specification-Version";
    public static final String MANIFEST_IMPLEMENTATION_VERSION = "Implementation-Version";
    public static final String MANIFEST_SPECIFICATION_TITLE = "Specification-Title";
    public static final String MANIFEST_IMPLEMENTATION_TITLE = "Implementation-Title";
    private final Resource resource;
    private Manifest manifest;

    public ShareManifest(Resource resource) {
        if (resource == null) {
            throw new IllegalArgumentException("Manifest 'resource' parameter must not be null.");
        } else {
            this.resource = resource;
        }
    }

    public void register() {
        super.register();
        this.readManifest();
    }

    public void readManifest() {
        try {
            InputStream is = this.resource.getInputStream();

            try {
                this.manifest = new Manifest(is);
            } catch (Throwable var5) {
                if (is != null) {
                    try {
                        is.close();
                    } catch (Throwable var4) {
                        var5.addSuppressed(var4);
                    }
                }

                throw var5;
            }

            if (is != null) {
                is.close();
            }

        } catch (IOException var6) {
            throw new RuntimeException("Error reading manifest.", var6);
        }
    }

    public String mainAttributeValue(String key) {
        String value = null;
        Attributes attributes = this.manifest.getMainAttributes();
        if (attributes != null) {
            value = attributes.getValue(key);
        }

        return value;
    }

    public Map<String, String> mainAttributesMap() {
        List<String> names = this.mainAttributeNames();
        Map<String, String> map = new HashMap(names.size());
        Iterator var3 = names.iterator();

        while(var3.hasNext()) {
            String name = (String)var3.next();
            String value = this.mainAttributeValue(name);
            map.put(name, value);
        }

        return map;
    }

    public List<String> mainAttributeNames() {
        List<String> names = Collections.emptyList();
        Attributes attributes = this.manifest.getMainAttributes();
        if (attributes != null) {
            names = this.namesToStrings(attributes.keySet());
        }

        return names;
    }

    public String attributeValue(String section, String key) {
        String value = null;
        Attributes attributes = this.manifest.getAttributes(section);
        if (attributes != null) {
            value = attributes.getValue(key);
        }

        return value;
    }

    public Map<String, String> attributesMap(String section) {
        List<String> names = this.attributeNames(section);
        Map<String, String> map = new HashMap(names.size());
        Iterator var4 = names.iterator();

        while(var4.hasNext()) {
            String name = (String)var4.next();
            String value = this.attributeValue(section, name);
            map.put(name, value);
        }

        return map;
    }

    public List<String> attributeNames(String section) {
        List<String> names = Collections.emptyList();
        Attributes attributes = this.manifest.getAttributes(section);
        if (attributes != null) {
            names = this.namesToStrings(attributes.keySet());
        }

        return names;
    }

    public Set<String> sectionNames() {
        return this.manifest.getEntries().keySet();
    }

    protected List<String> namesToStrings(Set<Object> names) {
        List<String> strings = new ArrayList(names.size());
        Iterator var3 = names.iterator();

        while(var3.hasNext()) {
            Object name = var3.next();
            if (!String.class.isAssignableFrom(name.getClass()) && !Attributes.Name.class.isAssignableFrom(name.getClass())) {
                throw new IllegalArgumentException("name parameter must be an Attributes.Name or String, but is " + name.getClass().getCanonicalName());
            }

            strings.add(name.toString());
        }

        return strings;
    }

    public String getSpecificationVersion() {
        return this.getVersion("Specification-Version");
    }

    public String getImplementationVersion() {
        return this.getVersion("Implementation-Version");
    }

    private String getVersion(String key) {
        String version = this.manifest.getMainAttributes().getValue(key);
        if (StringUtils.isEmpty(version)) {
            throw new AlfrescoRuntimeException("Invalid MANIFEST.MF: Share " + key + " is missing, are you using the valid MANIFEST.MF supplied with the Share.war?");
        } else {
            return version;
        }
    }
}
