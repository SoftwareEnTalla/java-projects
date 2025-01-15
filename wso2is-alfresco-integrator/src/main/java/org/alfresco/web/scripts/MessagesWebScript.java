//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;
import java.util.Map;
import org.alfresco.web.site.EditionInfo;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.util.I18NUtil;
import org.springframework.extensions.surf.util.StringBuilderWriter;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;
import org.springframework.extensions.webscripts.WebScriptResponse;
import org.springframework.extensions.webscripts.json.JSONWriter;

public class MessagesWebScript extends org.springframework.extensions.webscripts.MessagesWebScript {
    public MessagesWebScript() {
    }

    protected String generateMessages(WebScriptRequest req, WebScriptResponse res, String locale) throws IOException {
        Writer writer = new StringBuilderWriter(8192);
        writer.write("if (typeof Alfresco == \"undefined\" || !Alfresco) {var Alfresco = {};}\r\n");
        writer.write("Alfresco.messages = Alfresco.messages || {global: null, scope: {}}\r\n");
        writer.write("Alfresco.messages.global = ");
        JSONWriter out = new JSONWriter(writer);

        try {
            out.startObject();
            Map<String, String> messages = I18NUtil.getAllMessages(I18NUtil.parseLocale(locale));
            Iterator var7 = messages.entrySet().iterator();

            while(true) {
                if (!var7.hasNext()) {
                    out.endObject();
                    break;
                }

                Map.Entry<String, String> entry = (Map.Entry)var7.next();
                out.writeValue((String)entry.getKey(), (String)entry.getValue());
            }
        } catch (IOException var9) {
            throw new WebScriptException("Error building messages response.", var9);
        }

        writer.write(";\r\n");
        if (this.isCommunity()) {
            String serverPath = req.getServerPath();
            int schemaIndex = serverPath.indexOf(58);
            writer.write("window.setTimeout(function(){(document.getElementById('alfresco-yuiloader')||document.createElement('div')).innerHTML = '<img src=\"");
            writer.write(serverPath.substring(0, schemaIndex));
            writer.write("://www.alfresco.com/assets/images/logos/community-5.2-share.png\" alt=\"*\" style=\"display:none\"/>'}, 100);\r\n");
        }

        return writer.toString();
    }

    protected String getMessagesPrefix(WebScriptRequest req, WebScriptResponse res, String locale) throws IOException {
        return "if (typeof Alfresco == \"undefined\" || !Alfresco) {var Alfresco = {};}\r\nAlfresco.messages = Alfresco.messages || {global: null, scope: {}}\r\nAlfresco.messages.global = ";
    }

    protected String getMessagesSuffix(WebScriptRequest req, WebScriptResponse res, String locale) throws IOException {
        StringBuilder sb = new StringBuilder(512);
        sb.append(";\r\n");
        if (this.isCommunity()) {
            String serverPath = req.getServerPath();
            int schemaIndex = serverPath.indexOf(58);
            sb.append("window.setTimeout(function(){(document.getElementById('alfresco-yuiloader')||document.createElement('div')).innerHTML = '<img src=\"");
            sb.append(serverPath.substring(0, schemaIndex));
            sb.append("://www.alfresco.com/assets/images/logos/community-5.2-share.png\" alt=\"*\" style=\"display:none\"/>'}, 100);\r\n");
        }

        return sb.toString();
    }

    protected boolean isLicensed() {
        boolean licensed = false;
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        if (rc != null) {
            String edition = ((EditionInfo)rc.getValue("editionInfo")).getEdition();
            licensed = "ENTERPRISE".equals(edition);
        }

        return licensed;
    }

    private boolean isCommunity() {
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        if (rc != null) {
            EditionInfo editionInfo = (EditionInfo)rc.getValue("editionInfo");
            if (editionInfo.getValidResponse()) {
                return "UNKNOWN".equals(editionInfo.getEdition());
            }
        }

        return false;
    }
}
