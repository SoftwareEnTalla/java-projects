//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.ITopic;
import com.hazelcast.core.Message;
import com.hazelcast.core.MessageListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.alfresco.util.GUID;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.parser.ContainerFactory;
import org.json.simple.parser.JSONParser;
import org.springframework.extensions.surf.ModelObject;
import org.springframework.extensions.surf.ModelPersistenceContext;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.cache.ContentCache;
import org.springframework.extensions.surf.exception.ModelObjectPersisterException;
import org.springframework.extensions.surf.persister.PathStoreObjectPersister;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.ISO8601DateFormat;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.webscripts.json.JSONWriter;

public class ClusterAwarePathStoreObjectPersister extends PathStoreObjectPersister implements MessageListener<String> {
    private static Log logger = LogFactory.getLog(ClusterAwarePathStoreObjectPersister.class);
    private HazelcastInstance hazelcastInstance;
    private String hazelcastTopicName;
    private ITopic<String> clusterTopic = null;
    private static final String clusterNodeId = GUID.generate();

    public ClusterAwarePathStoreObjectPersister() {
    }

    public void setHazelcastInstance(HazelcastInstance hazelcastInstance) {
        this.hazelcastInstance = hazelcastInstance;
    }

    public void setHazelcastTopicName(String hazelcastTopicName) {
        this.hazelcastTopicName = hazelcastTopicName;
    }

    public void init(ModelPersistenceContext context) {
        super.init(context);
        if (this.hazelcastInstance == null) {
            throw new IllegalArgumentException("The hazelcastInstance property (HazelcastInstance) is mandatory.");
        } else if (this.hazelcastTopicName != null && this.hazelcastTopicName.length() != 0) {
            ITopic<String> topic = (ITopic<String>) this.hazelcastInstance.getTopic(this.hazelcastTopicName);
            if (topic == null) {
                throw new IllegalArgumentException("Did not find Hazelcast topic with name: '" + this.hazelcastTopicName + "' - cannot init.");
            } else {
                this.clusterTopic = topic;
                this.clusterTopic.addMessageListener(this);
            }
        } else {
            throw new IllegalArgumentException("The hazelcastTopicName property (String) is mandatory.");
        }
    }

    public boolean saveObject(ModelPersistenceContext context, ModelObject modelObject) throws ModelObjectPersisterException {
        boolean saved = super.saveObject(context, modelObject);
        if (saved) {
            this.addInvalidCachePath(this.generatePath(modelObject.getTypeId(), modelObject.getId()));
        }

        return saved;
    }

    public boolean removeObject(ModelPersistenceContext context, String objectTypeId, String objectId) throws ModelObjectPersisterException {
        boolean removed = super.removeObject(context, objectTypeId, objectId);
        if (removed) {
            this.addInvalidCachePath(this.generatePath(objectTypeId, objectId));
        }

        return removed;
    }

    protected ModelObject newObject(ModelPersistenceContext context, String objectTypeId, String objectId, boolean addToCache) throws ModelObjectPersisterException {
        ModelObject modelObject = super.newObject(context, objectTypeId, objectId, addToCache);
        if (modelObject != null) {
            this.addInvalidCachePath(this.generatePath(objectTypeId, objectId));
        }

        return modelObject;
    }

    private void addInvalidCachePath(String path) {
        if (logger.isDebugEnabled()) {
            logger.debug("Adding invalid cache path: " + path);
        }

        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        if (!(rc instanceof ClusterAwareRequestContext)) {
            throw new IllegalStateException("Incorrect Share cluster configuration detected - ClusterAwareRequestContextFactory is required.");
        } else {
            ((ClusterAwareRequestContext)rc).addInvalidCachePath(path);
        }
    }

    public void pushMessage(ClusterMessage message) {
        String msg = message.toString();
        if (logger.isDebugEnabled()) {
            logger.debug("Pushing message:\r\n" + msg);
        }

        this.clusterTopic.publish(msg);
    }

    public void onMessage(String message) {
        boolean debug = logger.isDebugEnabled();
        MessageProcessor proc = new MessageProcessor(message);
        if (!proc.isSender()) {
            if (debug) {
                logger.debug("Received message:\r\n" + message);
            }

            if ("cache-invalidation".equals(proc.getMessageType())) {
                if (debug) {
                    logger.debug("Processing message of type: " + proc.getMessageType());
                }

                List<String> paths = (List)proc.getMessagePayload().get("paths");
                if (paths != null) {
                    this.cacheLock.writeLock().lock();

                    try {
                        Iterator i1 = paths.iterator();

                        while(true) {
                            String path;
                            do {
                                if (!i1.hasNext()) {
                                    return;
                                }

                                path = (String)i1.next();
                                if (debug) {
                                    logger.debug("...invalidating cache for path: " + path);
                                }

                                this.objectCache.remove(path);
                            } while(this.caches.size() == 0);

                            Iterator i2 = this.caches.entrySet().iterator();

                            while(i2.hasNext()) {
                                Map.Entry<String, ContentCache<ModelObject>> entry = (Map.Entry)i2.next();
                                ((ContentCache)entry.getValue()).remove(path);
                            }
                        }
                    } finally {
                        this.cacheLock.writeLock().unlock();
                    }
                }
            } else {
                logger.warn("Received message of unknown type: " + proc.getMessageType());
            }
        }

    }

    @Override
    public void onMessage(Message<String> var1) {

    }

    static class MessageProcessor {
        private final String sender;
        private final String type;
        private final Map<String, Object> payload;

        MessageProcessor(String msg) {
            try {
                Map<String, Object> json = (Map)(new JSONParser()).parse(msg, new ContainerFactory() {
                    public Map createObjectContainer() {
                        return new HashMap();
                    }

                    public List creatArrayContainer() {
                        return new ArrayList();
                    }
                });
                this.sender = (String)json.get("sender");
                Map<String, Object> message = (Map)json.get("message");
                this.type = (String)message.get("type");
                this.payload = (Map)message.get("payload");
            } catch (Throwable var4) {
                throw new IllegalArgumentException("Unable to parse cluster JSON message: " + var4.getMessage() + "\r\n" + msg);
            }
        }

        boolean isSender() {
            return ClusterAwarePathStoreObjectPersister.clusterNodeId.equals(this.sender);
        }

        String getMessageType() {
            return this.type;
        }

        Map<String, Object> getMessagePayload() {
            return this.payload;
        }
    }

    static class PathInvalidationMessage extends BaseMessage {
        static final String TYPE = "cache-invalidation";
        static final String PAYLOAD_PATHS = "paths";

        PathInvalidationMessage(List<String> paths) {
            super("cache-invalidation", Collections.singletonMap("paths", paths));
        }
    }

    abstract static class BaseMessage implements ClusterMessage {
        private final String type;
        final Map<String, Object> payload;

        BaseMessage(String type, Map<String, Object> payload) {
            this.type = type;
            this.payload = payload;
        }

        public Map<String, Object> getPayload() {
            return this.payload;
        }

        public String getSender() {
            return ClusterAwarePathStoreObjectPersister.clusterNodeId;
        }

        public String getType() {
            return this.type;
        }

        public String toString() {
            try {
                StringBuilderWriter buffer = new StringBuilderWriter(512);
                JSONWriter writer = new JSONWriter(buffer);
                writer.startObject();
                writer.writeValue("sender", this.getSender());
                writer.startValue("message");
                writer.startObject();
                writer.writeValue("type", this.getType());
                writer.startValue("payload");
                serialiseMessageObjects(writer, (String)null, this.payload);
                writer.endValue();
                writer.endObject();
                writer.endValue();
                writer.endObject();
                return buffer.toString();
            } catch (IOException var3) {
                throw new IllegalStateException("Unable to output cluster message: " + var3.getMessage(), var3);
            }
        }

        static void serialiseMessageObjects(JSONWriter writer, String name, Object obj) throws IOException {
            if (obj instanceof Map) {
                if (name != null) {
                    writer.startValue(name);
                }

                writer.startObject();
                Map<String, Object> map = (Map)obj;
                Iterator i$ = map.keySet().iterator();

                while(i$.hasNext()) {
                    String key = (String)i$.next();
                    serialiseMessageObjects(writer, key, map.get(key));
                }

                writer.endObject();
                if (name != null) {
                    writer.endValue();
                }
            } else if (obj instanceof List) {
                if (name != null) {
                    writer.startValue(name);
                }

                writer.startArray();
                Iterator i$ = ((List)obj).iterator();

                while(i$.hasNext()) {
                    Object item = i$.next();
                    serialiseMessageObjects(writer, (String)null, item);
                }

                writer.endArray();
                if (name != null) {
                    writer.endValue();
                }
            } else if (obj instanceof Integer) {
                if (name != null) {
                    writer.writeValue(name, (Integer)obj);
                } else {
                    writer.writeValue((Integer)obj);
                }
            } else if (obj instanceof Boolean) {
                if (name != null) {
                    writer.writeValue(name, (Boolean)obj);
                } else {
                    writer.writeValue((Boolean)obj);
                }
            } else if (obj instanceof Date) {
                if (name != null) {
                    writer.writeValue(name, ISO8601DateFormat.format((Date)obj));
                } else {
                    writer.writeValue(ISO8601DateFormat.format((Date)obj));
                }
            } else if (obj == null) {
                if (name != null) {
                    writer.writeNullValue(name);
                } else {
                    writer.writeNullValue();
                }
            } else if (name != null) {
                writer.writeValue(name, obj.toString());
            } else {
                writer.writeValue(obj.toString());
            }

        }
    }

    interface ClusterMessage {
        String JSON_SENDER = "sender";
        String JSON_MESSAGE = "message";
        String JSON_TYPE = "type";
        String JSON_PAYLOAD = "payload";

        String getSender();

        String getType();

        Map<String, Object> getPayload();
    }
}
