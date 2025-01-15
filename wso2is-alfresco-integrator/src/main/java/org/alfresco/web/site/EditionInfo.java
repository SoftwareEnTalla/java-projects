//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import java.io.Serializable;
import org.json.JSONException;
import org.json.JSONObject;

public class EditionInfo implements Serializable {
    public static final String ENTERPRISE_EDITION = "ENTERPRISE";
    public static final String TEAM_EDITION = "TEAM";
    public static final String UNKNOWN_EDITION = "UNKNOWN";
    public static final String UNKNOWN_HOLDER = "UNKNOWN";
    protected final long users;
    protected final long documents;
    protected final String edition;
    protected final String holder;
    protected final boolean response;

    public EditionInfo() {
        this.users = -1L;
        this.documents = -1L;
        this.edition = "UNKNOWN";
        this.holder = "UNKNOWN";
        this.response = false;
    }

    public EditionInfo(String response) throws JSONException {
        JSONObject json = new JSONObject(response);
        if (json.has("data")) {
            String edition = "UNKNOWN";
            JSONObject data = json.getJSONObject("data");
            if (data != null && "ENTERPRISE".equalsIgnoreCase(data.getString("edition"))) {
                edition = "ENTERPRISE";
            }

            this.users = -1L;
            this.documents = -1L;
            this.holder = "UNKNOWN";
            this.edition = edition;
            this.response = false;
        } else {
            this.users = json.optLong("users", -1L);
            this.documents = json.optLong("documents", -1L);
            this.edition = json.getString("licenseMode");
            this.holder = json.getString("licenseHolder");
            this.response = true;
        }

    }

    public long getUsers() {
        return this.users;
    }

    public long getDocuments() {
        return this.documents;
    }

    public String getEdition() {
        return this.edition;
    }

    public String getHolder() {
        return this.holder;
    }

    public boolean getValidResponse() {
        return this.response;
    }

    public String toString() {
        return "Users: " + this.users + "  Documents: " + this.documents + "  Edition: " + this.edition + " Holder: " + this.holder + "  Built from server response: " + this.response;
    }
}
