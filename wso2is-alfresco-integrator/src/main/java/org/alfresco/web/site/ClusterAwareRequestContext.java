//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import java.util.ArrayList;
import java.util.List;
import org.springframework.extensions.surf.FrameworkBean;
import org.springframework.extensions.surf.LinkBuilder;
import org.springframework.extensions.surf.WebFrameworkServiceRegistry;
import org.springframework.extensions.surf.support.ServletRequestContext;

public class ClusterAwareRequestContext extends ServletRequestContext {
    private List<String> invalidCachePaths = new ArrayList();
    private ClusterAwarePathStoreObjectPersister clusterObjectPersister;

    public ClusterAwareRequestContext(ClusterAwarePathStoreObjectPersister clusterObjectPersister, WebFrameworkServiceRegistry serviceRegistry, FrameworkBean frameworkBean, LinkBuilder linkBuilder) {
        super(serviceRegistry, frameworkBean, linkBuilder);
        this.clusterObjectPersister = clusterObjectPersister;
    }

    void addInvalidCachePath(String path) {
        this.invalidCachePaths.add(path);
    }

    public void release() {
        try {
            if (this.invalidCachePaths.size() != 0) {
                ClusterAwarePathStoreObjectPersister.ClusterMessage msg = new ClusterAwarePathStoreObjectPersister.PathInvalidationMessage(this.invalidCachePaths);
                this.clusterObjectPersister.pushMessage(msg);
            }
        } finally {
            super.release();
        }

    }
}
