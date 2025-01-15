//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import com.google.common.base.Strings;
import java.io.Serializable;

public class UrlUtil implements Serializable {
    public static String alfrescoContext;
    public static String alfrescoPort;
    public static String alfrescoProtocol;
    public static String alfrescoHost;
    public static String alfrescoProxy;
    public static String shareContext;
    public static String sharePort;
    public static String shareProtocol;
    public static String shareHost;
    public static String shareProxy;
    private final String repoURL;
    private final String shareURL;

    public UrlUtil() {
        alfrescoContext = System.getProperty("alfresco.context");
        alfrescoPort = System.getProperty("alfresco.port");
        alfrescoProtocol = System.getProperty("alfresco.protocol");
        alfrescoHost = System.getProperty("alfresco.host");
        alfrescoProxy = System.getProperty("alfresco.proxy");
        shareContext = System.getProperty("share.context");
        sharePort = System.getProperty("share.port");
        shareProtocol = System.getProperty("share.protocol");
        shareHost = System.getProperty("share.host");
        shareProxy = System.getProperty("share.proxy");
        this.repoURL = this.getRepoURL();
        this.shareURL = this.getShareURL();
    }

    public String getRepoURL() {
        if (!Strings.isNullOrEmpty(alfrescoProxy)) {
            return alfrescoProxy;
        } else {
            return !Strings.isNullOrEmpty(alfrescoProtocol) && !Strings.isNullOrEmpty(alfrescoHost) && !Strings.isNullOrEmpty(alfrescoPort) ? alfrescoProtocol + "://" + alfrescoHost + ":" + alfrescoPort : "";
        }
    }

    public String getShareURL() {
        if (!Strings.isNullOrEmpty(shareProxy)) {
            return shareProxy;
        } else {
            return !Strings.isNullOrEmpty(shareProtocol) && !Strings.isNullOrEmpty(shareHost) && !Strings.isNullOrEmpty(sharePort) ? shareProtocol + "://" + shareHost + ":" + sharePort : "";
        }
    }
}
