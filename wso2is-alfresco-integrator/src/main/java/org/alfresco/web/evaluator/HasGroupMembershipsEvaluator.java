//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.evaluator;

import java.util.ArrayList;
import org.alfresco.web.extensibility.SlingshotEvaluatorUtil;
import org.json.simple.JSONObject;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;

public class HasGroupMembershipsEvaluator extends BaseEvaluator {
    protected SlingshotEvaluatorUtil util = null;
    private ArrayList<String> groups;
    private String relation = "AND";

    public HasGroupMembershipsEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public void setGroups(ArrayList<String> groups) {
        this.groups = groups;
    }

    public void setRelation(String relation) {
        this.relation = relation;
    }

    public boolean evaluate(JSONObject jsonObject) {
        boolean memberOfAllGroups = this.relation == null || this.relation.trim().equalsIgnoreCase("AND");
        RequestContext rc = ThreadLocalRequestContext.getRequestContext();
        boolean hasMembership = this.util.isMemberOfGroups(rc, this.groups, memberOfAllGroups);
        return hasMembership;
    }
}
