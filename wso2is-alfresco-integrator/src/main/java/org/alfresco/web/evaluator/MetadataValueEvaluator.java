//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import org.json.simple.JSONObject;

public class MetadataValueEvaluator extends BaseEvaluator {
    private Comparator comparator = null;
    private String accessor = null;

    public MetadataValueEvaluator() {
    }

    public void setComparator(Comparator comparator) {
        this.comparator = comparator;
    }

    public void setAccessor(String accessor) {
        this.accessor = accessor;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.comparator != null && this.accessor != null) {
            Object metaValue = this.getJSONValue(this.getMetadata(), this.accessor);
            return this.comparator.compare(metaValue);
        } else {
            return false;
        }
    }
}
