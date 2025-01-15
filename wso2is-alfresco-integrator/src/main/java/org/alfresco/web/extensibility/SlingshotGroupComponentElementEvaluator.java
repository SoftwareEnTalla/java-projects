//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.List;
import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.impl.DefaultSubComponentEvaluator;

public class SlingshotGroupComponentElementEvaluator extends DefaultSubComponentEvaluator {
    protected SlingshotEvaluatorUtil util = null;
    public static final String GROUPS = "groups";
    public static final String RELATION = "relation";
    public static final String AND = "AND";
    public static final String NEGATE = "negate";

    public SlingshotGroupComponentElementEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean evaluate(RequestContext context, Map<String, String> params) {
        boolean memberOfAllGroups = this.getRelationship(context, params);
        List<String> groups = this.util.getGroups((String)params.get("groups"));
        boolean isMember = this.util.isMemberOfGroups(context, groups, memberOfAllGroups);
        boolean negate = this.getNegation(context, params);
        boolean apply = isMember && !negate || !isMember && negate;
        return apply;
    }

    protected boolean getNegation(RequestContext context, Map<String, String> evaluationProperties) {
        String negateParam = (String)evaluationProperties.get("negate");
        return negateParam != null && negateParam.trim().equalsIgnoreCase(Boolean.TRUE.toString());
    }

    protected boolean getRelationship(RequestContext context, Map<String, String> evaluationProperties) {
        String relationParam = (String)evaluationProperties.get("relation");
        return relationParam != null && relationParam.trim().equalsIgnoreCase("AND");
    }
}
