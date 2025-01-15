//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import jakarta.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.alfresco.web.scripts.ShareManifest;
import org.alfresco.web.site.servlet.MTAuthenticationFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.springframework.extensions.config.ConfigBootstrap;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.exception.WebFrameworkServiceException;
import org.springframework.extensions.surf.mvc.AbstractWebFrameworkInterceptor;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.ui.ModelMap;
import org.springframework.web.context.request.WebRequest;

public class EditionInterceptor extends AbstractWebFrameworkInterceptor {
    public static final String EDITION_INFO = "editionInfo";
    public static final String KEY_DOCS_EDITION = "docsEdition";
    public static final String URL_UTIL = "urlUtil";
    public static final String ENTERPRISE_EDITION = "ENTERPRISE";
    public static final String TEAM_EDITION = "TEAM";
    public static final String UNKNOWN_EDITION = "UNKNOWN";
    public static final String UNKNOWN_HOLDER = "UNKNOWN";
    private static Log logger = LogFactory.getLog(EditionInterceptor.class);
    private static EditionInfo EDITIONINFO = null;
    private static DocsEdition docsEdition = null;
    private static UrlUtil urlUtil = new UrlUtil();
    private static volatile boolean outputInfo = false;
    private static volatile boolean outputEditionInfo = false;
    private static final ReadWriteLock editionLock = new ReentrantReadWriteLock();
    private ShareManifest shareManifest;

    public EditionInterceptor() {
    }

    public void setShareManifest(ShareManifest shareManifest) {
        this.shareManifest = shareManifest;
    }

    public void preHandle(WebRequest request) throws Exception {
        editionLock.readLock().lock();

        try {
            if (EDITIONINFO == null) {
                editionLock.readLock().unlock();
                editionLock.writeLock().lock();

                try {
                    if (EDITIONINFO == null) {
                        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
                        Connector conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco");
                        ConnectorContext ctx = new ConnectorContext();
                        ctx.setExceptionOnError(false);
                        Response response = conn.call("/api/admin/restrictions?guest=true");
                        if (response.getStatus().getCode() == 401 && MTAuthenticationFilter.getCurrentServletRequest() != null) {
                            HttpSession session = MTAuthenticationFilter.getCurrentServletRequest().getSession(false);
                            if (session != null && session.getAttribute("_alf_USER_ID") != null) {
                                conn = rc.getServiceRegistry().getConnectorService().getConnector("alfresco", (String)session.getAttribute("_alf_USER_ID"), session);
                                response = conn.call("/api/admin/restrictions");
                            } else {
                                response = conn.call("/api/server");
                            }
                        }

                        EditionInfo editionInfo;
                        if (response.getStatus().getCode() == 200) {
                            editionInfo = new EditionInfo(response.getResponse());
                            docsEdition = new DocsEdition(editionInfo.getEdition(), this.shareManifest.getSpecificationVersion(), false);
                            if (editionInfo.getValidResponse()) {
                                logger.info("Successfully retrieved license information from Alfresco.");
                                EDITIONINFO = editionInfo;
                            } else {
                                if (!outputEditionInfo) {
                                    logger.info("Successfully retrieved edition information from Alfresco.");
                                    outputEditionInfo = true;
                                }

                                ThreadLocalRequestContext.getRequestContext().setValue("editionInfo", editionInfo);
                                ThreadLocalRequestContext.getRequestContext().setValue("docsEdition", docsEdition);
                                ThreadLocalRequestContext.getRequestContext().setValue("urlUtil", urlUtil);
                            }

                            String runtimeConfig = null;
                            if ("TEAM".equals(editionInfo.getEdition())) {
                                runtimeConfig = "classpath:alfresco/team-config.xml";
                            } else if ("ENTERPRISE".equals(editionInfo.getEdition())) {
                                runtimeConfig = "classpath:alfresco/enterprise-config.xml";
                            }

                            if (runtimeConfig != null) {
                                List<String> configs = new ArrayList(1);
                                configs.add(runtimeConfig);
                                ConfigService configservice = rc.getServiceRegistry().getConfigService();
                                ConfigBootstrap cb = new ConfigBootstrap();
                                cb.setBeanName("share-edition-config");
                                cb.setConfigService(configservice);
                                cb.setConfigs(configs);
                                cb.register();
                                configservice.reset();
                            }

                            if (logger.isDebugEnabled()) {
                                logger.debug("Current EditionInfo: " + editionInfo);
                            }
                        } else {
                            if (!outputInfo) {
                                logger.info("Unable to retrieve License information from Alfresco: " + response.getStatus().getCode());
                                outputInfo = true;
                            }

                            editionInfo = new EditionInfo();
                            ThreadLocalRequestContext.getRequestContext().setValue("editionInfo", editionInfo);
                            DocsEdition tempDocsEdition = new DocsEdition();
                            ThreadLocalRequestContext.getRequestContext().setValue("docsEdition", tempDocsEdition);
                            if (logger.isDebugEnabled()) {
                                logger.debug("Current EditionInfo: " + editionInfo);
                            }
                        }
                    }
                } catch (JSONException var19) {
                    throw new WebFrameworkServiceException("Unable to process response: " + var19.getMessage(), var19);
                } finally {
                    editionLock.readLock().lock();
                    editionLock.writeLock().unlock();
                }
            }

            if (EDITIONINFO != null) {
                ThreadLocalRequestContext.getRequestContext().setValue("editionInfo", EDITIONINFO);
                ThreadLocalRequestContext.getRequestContext().setValue("docsEdition", docsEdition);
                ThreadLocalRequestContext.getRequestContext().setValue("urlUtil", urlUtil);
            }
        } finally {
            editionLock.readLock().unlock();
        }

    }

    public void postHandle(WebRequest request, ModelMap model) throws Exception {
    }

    public void afterCompletion(WebRequest request, Exception ex) throws Exception {
    }
}
