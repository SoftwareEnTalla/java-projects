//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.springframework.extensions.surf.exception.ConnectorServiceException;

public class TaskTypeEvaluator extends ServiceBasedEvaluator {
    protected static final String JSON_DATA = "data";
    protected static final String JSON_DEFINITION = "definition";
    protected static final String JSON_TYPE = "type";
    protected static final String JSON_NAME = "name";
    protected static final Pattern taskIdPattern = Pattern.compile(".+\\$([0-9]+|start[0-9]+)");
    private static Log logger = LogFactory.getLog(TaskTypeEvaluator.class);

    public TaskTypeEvaluator() {
    }

    protected Log getLogger() {
        return logger;
    }

    public boolean applies(Object obj, String condition) {
        boolean result = false;
        if (condition == null) {
            if (this.getLogger().isWarnEnabled()) {
                this.getLogger().warn("Expected 'condition' (task type) but was passed null value. Please check config for errors.");
            }
        } else if (obj instanceof String) {
            String taskId = (String)obj;
            Matcher m = taskIdPattern.matcher(taskId);
            if (m.matches()) {
                try {
                    String type = null;
                    String jsonResponseString = this.callService("/api/task-instances/" + taskId);
                    if (jsonResponseString != null) {
                        JSONObject json = new JSONObject(new JSONTokener(jsonResponseString));
                        if (json.has("data")) {
                            JSONObject dataObj = json.getJSONObject("data");
                            if (dataObj.has("definition")) {
                                JSONObject defObj = dataObj.getJSONObject("definition");
                                if (defObj.has("type")) {
                                    JSONObject typeObj = defObj.getJSONObject("type");
                                    if (typeObj.has("name")) {
                                        type = typeObj.getString("name");
                                        result = condition.equals(type);
                                    }
                                }
                            }
                        }

                        if (type == null && this.getLogger().isWarnEnabled()) {
                            this.getLogger().warn("Failed to find task type for '" + taskId + "' in JSON response from task instances service");
                        }
                    } else if (this.getLogger().isWarnEnabled()) {
                        this.getLogger().warn("Task instances service response appears to be null for '" + taskId + "'");
                    }
                } catch (ServiceBasedEvaluator.NotAuthenticatedException var12) {
                } catch (ConnectorServiceException var13) {
                    if (this.getLogger().isWarnEnabled()) {
                        this.getLogger().warn("Failed to connect to task instances service.", var13);
                    }
                } catch (JSONException var14) {
                    if (this.getLogger().isWarnEnabled()) {
                        this.getLogger().warn("Failed to find task type for '" + taskId + "' in JSON response from task instances service.", var14);
                    }
                }
            }
        }

        return result;
    }
}
