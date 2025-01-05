//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import org.springframework.extensions.surf.LinkBuilder;
import org.springframework.extensions.surf.support.ServletRequestContext;
import org.springframework.extensions.surf.support.ServletRequestContextFactory;

public class ClusterAwareRequestContextFactory extends ServletRequestContextFactory {
    private ClusterAwarePathStoreObjectPersister clusterObjectPersister;

    public ClusterAwareRequestContextFactory() {
    }

    public void setClusterObjectPersister(ClusterAwarePathStoreObjectPersister clusterObjectPersister) {
        this.clusterObjectPersister = clusterObjectPersister;
    }

    protected ServletRequestContext buildServletRequestContext(LinkBuilder linkBuilder) {
        this.setConfigService(this.webFrameworkServiceRegistry.getConfigService());
        return new ClusterAwareRequestContext(this.clusterObjectPersister, this.webFrameworkServiceRegistry, this.frameworkUtils, linkBuilder);
    }
}
