//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import org.alfresco.web.resolver.doclib.DoclistActionGroupResolver;
import org.alfresco.web.resolver.doclib.DoclistDataUrlResolver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public class ResolverHelper extends BaseProcessorExtension implements ApplicationContextAware {
    private static Log logger = LogFactory.getLog(ActionEvaluatorHelper.class);
    protected ApplicationContext applicationContext = null;

    public ResolverHelper() {
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    public DoclistDataUrlResolver getDoclistDataUrlResolver(String resolverName) {
        try {
            DoclistDataUrlResolver resolver = (DoclistDataUrlResolver)this.applicationContext.getBean(resolverName);
            if (resolver == null) {
                logger.warn("Bean with id '" + resolverName + "' does not implement DoclistDataUrlResolver interface.");
                return null;
            } else {
                return resolver;
            }
        } catch (Exception var3) {
            logger.warn("DoclistDataUrlResolver '" + resolverName + "' not found.");
            if (logger.isDebugEnabled()) {
                logger.debug("Exception when trying to get doclistDataUrlResolver '" + resolverName + "':", var3);
            }

            return null;
        }
    }

    public DoclistActionGroupResolver getDoclistActionGroupResolver(String resolverName) {
        try {
            DoclistActionGroupResolver resolver = (DoclistActionGroupResolver)this.applicationContext.getBean(resolverName);
            if (resolver == null) {
                logger.warn("Bean with id '" + resolverName + "' does not implement DoclistActionGroupResolver interface.");
                return null;
            } else {
                return resolver;
            }
        } catch (Exception var3) {
            logger.warn("DoclistActionGroupResolver '" + resolverName + "' not found.");
            return null;
        }
    }
}
