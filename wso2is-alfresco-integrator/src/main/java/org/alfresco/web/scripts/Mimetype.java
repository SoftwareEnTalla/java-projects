//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

class Mimetype {
    private final String mimetype;
    private final String description;
    private final String defaultExtension;
    private final List<String> additionalExtensions;

    Mimetype(String mimetype, JSONObject json) throws JSONException {
        this.mimetype = mimetype;
        this.description = json.getString("description");
        JSONObject ext = json.getJSONObject("extensions");
        this.defaultExtension = ext.getString("default");
        JSONArray additional = ext.getJSONArray("additional");
        this.additionalExtensions = new ArrayList(additional.length());

        for(int i = 0; i < additional.length(); ++i) {
            this.additionalExtensions.add(additional.getString(i));
        }

    }

    public String getMimetype() {
        return this.mimetype;
    }

    public String getDescription() {
        return this.description;
    }

    public String getDefaultExtension() {
        return this.defaultExtension;
    }

    public List<String> getAdditionalExtensions() {
        return this.additionalExtensions;
    }
}
