//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import java.util.ListIterator;
import org.json.simple.JSONObject;

public class VirtualChainedMatchOneEvaluator extends VirtualBaseEvaluator {
    private ArrayList<Evaluator> evaluators = null;

    public VirtualChainedMatchOneEvaluator() {
    }

    public void setEvaluators(ArrayList<Evaluator> evaluators) {
        this.evaluators = evaluators;
    }

    public boolean evaluate(JSONObject jsonObject) {
        if (this.notInVirtualContext(jsonObject)) {
            return true;
        } else {
            boolean result = false;
            BaseEvaluator evaluator;
            if (this.evaluators != null) {
                for(ListIterator<Evaluator> evalIter = this.evaluators.listIterator(); !result && evalIter.hasNext(); result = evaluator.negateOutput ^ evaluator.evaluate(jsonObject)) {
                    evaluator = (BaseEvaluator)evalIter.next();
                    evaluator.args = this.args;
                    evaluator.metadata = this.metadata;
                }
            }

            return result;
        }
    }
}
