//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.extensibility;

import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.extensibility.ExtensionModuleEvaluator;

public class SlingshotSiteModuleEvaluator implements ExtensionModuleEvaluator {
    private static Log logger = LogFactory.getLog(SlingshotSiteModuleEvaluator.class);
    public static final String SITE_PRESET_FILTER = "sitePresets";
    public static final String SITE_FILTER = "sites";
    public static final String APPLY_FOR_NON_SITES = "applyForNonSites";
    public static final String GROUPS = "groups";
    public static final String GROUPS_RELATION = "groupsRelation";
    public static final String GROUPS_RELATION_AND = "AND";
    protected SlingshotEvaluatorUtil util = null;

    public SlingshotSiteModuleEvaluator() {
    }

    public void setSlingshotEvaluatorUtil(SlingshotEvaluatorUtil slingshotExtensibilityUtil) {
        this.util = slingshotExtensibilityUtil;
    }

    public String[] getRequiredProperties() {
        String[] properties = new String[]{"sitePresets", "sites"};
        return properties;
    }

    public boolean applyModule(RequestContext context, Map<String, String> params) {
        String siteId = this.util.getSite(context);
        if (siteId != null) {
            if (!siteId.matches(this.util.getEvaluatorParam(params, "sites", ".*"))) {
                return false;
            } else {
                String sitePreset = this.util.getSitePreset(context, siteId);
                if (sitePreset != null && sitePreset.matches(this.util.getEvaluatorParam(params, "sitePresets", ".*"))) {
                    return this.isUserInGroups(context, params);
                } else {
                    return false;
                }
            }
        } else if (!this.util.getEvaluatorParam(params, "applyForNonSites", "true").equals("true")) {
            return false;
        } else {
            return this.isUserInGroups(context, params);
        }
    }

    protected boolean isUserInGroups(RequestContext context, Map<String, String> params) {
        String groupsParam = this.util.getEvaluatorParam(params, "groups", ".*");
        if (groupsParam.equals(".*")) {
            return true;
        } else {
            String relationParam = (String)params.get("groupsRelation");
            boolean memberOfAllGroups = relationParam != null && relationParam.trim().equalsIgnoreCase("AND");
            List<String> groups = this.util.getGroups(groupsParam);
            return this.util.isMemberOfGroups(context, groups, memberOfAllGroups);
        }
    }
}
