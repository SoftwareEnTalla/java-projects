//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.config.forms;

public class ConstraintHandlerDefinition {
    private String type;
    private String validationHandler;
    private String message;
    private String messageId;
    private String event;

    public ConstraintHandlerDefinition(String type, String validationHandler, String msg, String msgId, String event) {
        this.type = type == null ? "" : type;
        this.validationHandler = validationHandler;
        this.message = msg;
        this.messageId = msgId;
        this.event = event;
    }

    public String getType() {
        return this.type;
    }

    public String getValidationHandler() {
        return this.validationHandler;
    }

    public String getMessage() {
        return this.message;
    }

    public String getMessageId() {
        return this.messageId;
    }

    public String getEvent() {
        return this.event;
    }

    void setValidationHandler(String validationHandler) {
        this.validationHandler = validationHandler;
    }

    void setMessage(String message) {
        this.message = message;
    }

    void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    void setEvent(String event) {
        this.event = event;
    }

    public String toString() {
        StringBuilder result = new StringBuilder();
        result.append(this.type).append(", ").append(this.validationHandler).append(", ").append(this.message).append(", ").append(this.messageId).append(", ").append(this.event);
        return result.toString();
    }
}
