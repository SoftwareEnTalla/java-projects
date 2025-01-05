//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import org.apache.commons.logging.Log;

public class TaskUtils {
    public TaskUtils() {
    }

    public static <E extends Throwable> void retry(int maxRetries, Task<E> task) throws E {
        retry(maxRetries, 0L, (Log)null, task);
    }

    public static <E extends Throwable> void retry(int maxRetries, long waitTimeMs, Log logger, Task<E> task) throws E {
        while(maxRetries > 0) {
            --maxRetries;

            try {
                task.run();
            } catch (Exception var9) {
                Exception e = var9;
                if (maxRetries == 0) {
                    try {
                        throw e;
                    } catch (Exception var7) {
                        throw new RuntimeException(var9);
                    }
                }

                if (logger != null) {
                    logger.info("Attempt " + maxRetries + " failed", var9);
                }

                try {
                    Thread.sleep(waitTimeMs);
                } catch (InterruptedException var8) {
                    logger.error(var8.getMessage());
                }
            }
        }

    }

    public interface Task<E extends Throwable> {
        void run() throws E;
    }
}
