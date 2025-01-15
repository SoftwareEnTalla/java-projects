//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import org.alfresco.web.evaluator.Evaluator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public class ActionEvaluatorHelper extends BaseProcessorExtension implements ApplicationContextAware {
    private static Log logger = LogFactory.getLog(ActionEvaluatorHelper.class);
    protected ApplicationContext applicationContext = null;

    public ActionEvaluatorHelper() {
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    public Evaluator getEvaluator(String evaluatorName) {
        try {
            Evaluator evaluator = (Evaluator)this.applicationContext.getBean(evaluatorName);
            if (!(evaluator instanceof Evaluator)) {
                logger.warn("Bean with id '" + evaluatorName + "' does not implement Evaluator interface.");
                return null;
            } else {
                return evaluator;
            }
        } catch (Exception var3) {
            logger.warn("Evaluator '" + evaluatorName + "' not found.");
            if (logger.isDebugEnabled()) {
                logger.debug("Exception when trying to get evaluator '" + evaluatorName + "':", var3);
            }

            return null;
        }
    }
}
