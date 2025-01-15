//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.topic.ITopic;
import com.hazelcast.topic.Message;
import com.hazelcast.topic.MessageListener;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
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
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.surf.ClusterMessageAware;
import org.springframework.extensions.surf.ClusterService;
import org.springframework.extensions.surf.util.ISO8601DateFormat;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.webscripts.json.JSONWriter;

public class ClusterTopicService implements MessageListener<String>, ClusterService, ApplicationContextAware {
    private static Log logger = LogFactory.getLog(ClusterTopicService.class);
    private HazelcastInstance hazelcastInstance;
    private String hazelcastTopicName;
    private ITopic<String> clusterTopic = null;
    private Map<String, ClusterMessageAware> clusterBeans = null;
    private static final String clusterNodeId = GUID.generate();
    private ApplicationContext applicationContext = null;

    public ClusterTopicService() {
    }

    public void setHazelcastInstance(HazelcastInstance hazelcastInstance) {
        this.hazelcastInstance = hazelcastInstance;
    }

    public void setHazelcastTopicName(String hazelcastTopicName) {
        this.hazelcastTopicName = hazelcastTopicName;
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    public void init() {
        if (this.hazelcastInstance == null) {
            throw new IllegalArgumentException("The 'hazelcastInstance' property (HazelcastInstance) is mandatory.");
        } else if (this.hazelcastTopicName != null && this.hazelcastTopicName.length() != 0) {
            ITopic<String> topic = this.hazelcastInstance.getTopic(this.hazelcastTopicName);
            if (topic == null) {
                throw new IllegalArgumentException("Did not find Hazelcast topic with name: '" + this.hazelcastTopicName + "' - cannot init.");
            } else {
                Map<String, ClusterMessageAware> beans = this.applicationContext.getBeansOfType(ClusterMessageAware.class);
                this.clusterBeans = new HashMap();

                Iterator var3;
                String id;
                ClusterMessageAware bean;
                for(var3 = beans.keySet().iterator(); var3.hasNext(); bean.setClusterService(this)) {
                    id = (String)var3.next();
                    bean = (ClusterMessageAware)beans.get(id);
                    String messageType = bean.getClusterMessageType();
                    if (messageType != null) {
                        if (this.clusterBeans.containsKey(messageType)) {
                            throw new IllegalStateException("ClusterMessageAware bean with id '" + id + "' attempted to register with existing Message Type: " + messageType);
                        }

                        this.clusterBeans.put(messageType, bean);
                    }
                }

                if (logger.isDebugEnabled()) {
                    logger.debug("Registered beans for cluster messages:");
                    var3 = beans.keySet().iterator();

                    while(var3.hasNext()) {
                        id = (String)var3.next();
                        logger.debug(id + " [" + ((ClusterMessageAware)beans.get(id)).getClusterMessageType() + "]");
                    }
                }

                this.clusterTopic = topic;
                this.clusterTopic.addMessageListener(this);
                logger.info("Init complete for Hazelcast cluster - listening on topic: " + this.hazelcastTopicName);
            }
        } else {
            throw new IllegalArgumentException("The 'hazelcastTopicName' property (String) is mandatory.");
        }
    }

    public void publishClusterMessage(String messageType, Map<String, Serializable> payload) {
        ClusterMessage msg = new ClusterMessageImpl(messageType, payload);
        String serialised = msg.toString();
        if (logger.isDebugEnabled()) {
            logger.debug("Pushing message:\r\n" + serialised);
        }

        this.clusterTopic.publish(serialised);
    }

    public void onMessage(Message<String> message) {
        boolean debug = logger.isDebugEnabled();
        String msg = (String)message.getMessageObject();
        MessageProcessor proc = new MessageProcessor(msg);
        if (!proc.isSender()) {
            if (debug) {
                Log var10000 = logger;
                String var10001 = proc.getMessageType();
                var10000.debug("Received message of type:" + var10001 + "\r\n" + msg);
            }

            ClusterMessageAware bean = (ClusterMessageAware)this.clusterBeans.get(proc.getMessageType());
            if (bean != null) {
                bean.onClusterMessage(proc.getMessagePayload());
            } else {
                logger.warn("Received message of unknown type - no handler bean found: " + proc.getMessageType());
            }
        }

    }

    static class ClusterMessageImpl implements ClusterMessage {
        private final String type;
        final Map<String, Serializable> payload;

        ClusterMessageImpl(String type, Map<String, Serializable> payload) {
            this.type = type;
            this.payload = payload;
        }

        public Map<String, Serializable> getPayload() {
            return this.payload;
        }

        public String getSender() {
            return ClusterTopicService.clusterNodeId;
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
                serialiseMessageObjects(writer, (String)null, (Serializable)this.payload);
                writer.endValue();
                writer.endObject();
                writer.endValue();
                writer.endObject();
                return buffer.toString();
            } catch (IOException var3) {
                throw new IllegalStateException("Failed to serialise cluster message: " + var3.getMessage(), var3);
            }
        }

        static void serialiseMessageObjects(JSONWriter writer, String name, Serializable obj) throws IOException {
            if (obj instanceof Map) {
                if (name != null) {
                    writer.startValue(name);
                }

                writer.startObject();
                Map<String, Serializable> map = (Map)obj;
                Iterator var4 = map.keySet().iterator();

                while(var4.hasNext()) {
                    String key = (String)var4.next();
                    serialiseMessageObjects(writer, key, (Serializable)map.get(key));
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
                Iterator var6 = ((List)obj).iterator();

                while(var6.hasNext()) {
                    Object item = var6.next();
                    serialiseMessageObjects(writer, (String)null, (Serializable)item);
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

    static class MessageProcessor {
        private final String sender;
        private final String type;
        private final Map<String, Serializable> payload;

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
                String var10002 = var4.getMessage();
                throw new IllegalArgumentException("Unable to parse cluster JSON message: " + var10002 + "\r\n" + msg);
            }
        }

        boolean isSender() {
            return ClusterTopicService.clusterNodeId.equals(this.sender);
        }

        String getMessageType() {
            return this.type;
        }

        Map<String, Serializable> getMessagePayload() {
            return this.payload;
        }
    }

    interface ClusterMessage {
        String JSON_SENDER = "sender";
        String JSON_MESSAGE = "message";
        String JSON_TYPE = "type";
        String JSON_PAYLOAD = "payload";

        String getSender();

        String getType();

        Map<String, Serializable> getPayload();
    }
}
