//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.List;
import java.util.Map;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.ExtensionModuleEvaluator;

public class SlingshotGroupModuleEvaluator implements ExtensionModuleEvaluator {
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotGroupModuleEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public boolean applyModule(RequestContext context, Map<String, String> evaluationProperties) {
        boolean memberOfAllGroups = this.getRelationship(context, evaluationProperties);
        List<String> groups = this.util.getGroups((String)evaluationProperties.get("groups"));
        boolean isMember = this.util.isMemberOfGroups(context, groups, memberOfAllGroups);
        boolean negate = this.getNegation(context, evaluationProperties);
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

    public String[] getRequiredProperties() {
        String[] props = new String[]{"groups", "relation", "negate"};
        return props;
    }
}
