//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.alfresco.error.AlfrescoRuntimeException;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.webscripts.processor.BaseProcessorExtension;

public abstract class SingletonValueProcessorExtension<T> extends BaseProcessorExtension {
    private final Map<String, T> storeValues = new HashMap();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    public SingletonValueProcessorExtension() {
    }

    protected final T getSingletonValue() {
        return this.getSingletonValue(false);
    }

    protected final T getSingletonValue(boolean tenant) {
        return this.getSingletonValue(tenant, ThreadLocalRequestContext.getRequestContext().getUserId());
    }

    protected final T getSingletonValue(boolean tenant, String userId) {
        String storeId = tenant ? this.getTenantUserStore(userId) : "";
        this.lock.readLock().lock();

        Object result;
        try {
            result = this.storeValues.get(storeId);
            if (result == null) {
                this.lock.readLock().unlock();
                this.lock.writeLock().lock();

                try {
                    String var10002;
                    try {
                        result = this.storeValues.get(storeId);
                        if (result == null) {
                            result = this.retrieveValue(userId, storeId);
                            this.storeValues.put(storeId, (T) result);
                        }
                    } catch (ConnectorServiceException var16) {
                        var10002 = this.getValueName();
                        throw new AlfrescoRuntimeException("Unable to retrieve " + var10002 + " configuration from Alfresco: " + var16.getMessage());
                    } catch (Exception var17) {
                        var10002 = this.getValueName();
                        throw new AlfrescoRuntimeException("Failed during processing of " + var10002 + " configuration from Alfresco: " + var17.getMessage());
                    }
                } finally {
                    this.lock.readLock().lock();
                    this.lock.writeLock().unlock();
                }
            }
        } finally {
            this.lock.readLock().unlock();
        }

        return result!=null?(T) result:null;
    }

    protected final boolean hasSingletonValue(boolean tenant, String userId) {
        boolean result = false;
        String storeId = tenant ? this.getTenantUserStore(userId) : "";
        this.lock.readLock().lock();

        try {
            result = this.storeValues.get(storeId) != null;
        } finally {
            this.lock.readLock().unlock();
        }

        return result;
    }

    protected abstract T retrieveValue(String var1, String var2) throws ConnectorServiceException;

    protected abstract String getValueName();

    private final String getTenantUserStore(String userId) {
        if (userId != null && !AuthenticationUtil.isGuest(userId)) {
            String storeId = "";
            int idx = userId.indexOf(64);
            if (idx != -1) {
                storeId = userId.substring(idx);
            }

            return storeId;
        } else {
            throw new AlfrescoRuntimeException("User ID must exist and cannot be guest.");
        }
    }
}
