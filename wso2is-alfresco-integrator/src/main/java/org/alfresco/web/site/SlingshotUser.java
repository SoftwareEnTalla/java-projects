//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site;

import java.util.Map;
import org.springframework.extensions.surf.FrameworkUtil;
import org.springframework.extensions.surf.exception.PlatformRuntimeException;
import org.springframework.extensions.surf.exception.UserFactoryException;
import org.springframework.extensions.surf.site.AlfrescoUser;

public class SlingshotUser extends AlfrescoUser {
    public SlingshotUser(String id, Map<String, Boolean> capabilities, Map<String, Boolean> immutability) {
        super(id, capabilities, immutability);
    }

    public void save() {
        try {
            ((SlingshotUserFactory)FrameworkUtil.getServiceRegistry().getUserFactory()).saveUser(this);
        } catch (UserFactoryException var2) {
            throw new PlatformRuntimeException("Unable to save user details: " + var2.getMessage(), var2);
        }
    }
}
