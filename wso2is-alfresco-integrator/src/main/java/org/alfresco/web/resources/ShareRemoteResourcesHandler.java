//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.resources;

import org.springframework.extensions.surf.RemoteResourcesHandler;

public class ShareRemoteResourcesHandler extends RemoteResourcesHandler {
    private String repositoryPrefix;
    public static final String FILTER = "js/alfresco/";
    public static final int FILTER_LENGTH = "js/alfresco/".length();

    public ShareRemoteResourcesHandler() {
    }

    public String getRepositoryPrefix() {
        return this.repositoryPrefix;
    }

    public void setRepositoryPrefix(String repositoryPrefix) {
        this.repositoryPrefix = repositoryPrefix;
    }

    protected String processPath(String path) {
        StringBuilder processedPath = new StringBuilder(this.getRepositoryPrefix());
        if (path.startsWith("js/alfresco/")) {
            processedPath.append(path.substring(FILTER_LENGTH));
        }

        return processedPath.toString();
    }
}
