//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import java.util.Iterator;
import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.web.scripts.DictionaryQuery;
import org.json.simple.JSONObject;

public class NodeTypeEvaluator extends BaseEvaluator {
    private DictionaryQuery dictionary;
    private boolean allowSubtypes = true;
    private ArrayList<String> types;

    public NodeTypeEvaluator() {
    }

    public void setDictionary(DictionaryQuery dictionary) {
        this.dictionary = dictionary;
    }

    public void setAllowSubtypes(boolean allowSubtypes) {
        this.allowSubtypes = allowSubtypes;
    }

    public void setTypes(ArrayList<String> types) {
        this.types = types;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.types.size() == 0) {
            return false;
        } else {
            String nodeType = this.getNodeType(jsonObject);

            try {
                if (this.types.contains(nodeType)) {
                    return true;
                } else {
                    if (this.allowSubtypes && this.dictionary != null) {
                        Iterator var3 = this.types.iterator();

                        while(var3.hasNext()) {
                            String type = (String)var3.next();
                            if (this.dictionary.isSubType(nodeType, type)) {
                                return true;
                            }
                        }
                    }

                    return false;
                }
            } catch (Exception var5) {
                throw new AlfrescoRuntimeException("Failed to run action evaluator: " + var5.getMessage());
            }
        }
    }
}
