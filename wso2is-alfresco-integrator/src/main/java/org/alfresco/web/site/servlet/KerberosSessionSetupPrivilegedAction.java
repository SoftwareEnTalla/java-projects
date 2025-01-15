//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet;

import java.security.PrivilegedAction;
import org.alfresco.jlan.server.auth.kerberos.KerberosDetails;
import org.alfresco.jlan.server.auth.spnego.OID;
import org.alfresco.util.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.springframework.extensions.surf.util.Base64;

public class KerberosSessionSetupPrivilegedAction implements PrivilegedAction<Pair<KerberosDetails, String>> {
    private static final Log logger = LogFactory.getLog(KerberosSessionSetupPrivilegedAction.class);
    private byte[] m_secBlob;
    private int m_secOffset;
    private int m_secLen;
    private String m_accountName;
    private String endpointSPN;

    public KerberosSessionSetupPrivilegedAction(String accountName, byte[] secBlob, String endpointSPN) {
        this.m_accountName = accountName;
        this.m_secBlob = secBlob;
        this.m_secOffset = 0;
        this.m_secLen = secBlob.length;
        this.endpointSPN = endpointSPN;
    }

    public Pair<KerberosDetails, String> run() {
        KerberosDetails krbDetails = null;

        try {
            GSSManager gssManager = GSSManager.getInstance();
            GSSName serverGSSName = gssManager.createName(this.m_accountName, GSSName.NT_USER_NAME);
            GSSCredential serverGSSCreds = gssManager.createCredential(serverGSSName, Integer.MAX_VALUE, OID.KERBEROS5, 2);
            GSSContext serverGSSContext = gssManager.createContext(serverGSSCreds);
            byte[] respBlob = serverGSSContext.acceptSecContext(this.m_secBlob, this.m_secOffset, this.m_secLen);
            krbDetails = new KerberosDetails(serverGSSContext.getSrcName(), serverGSSContext.getTargName(), respBlob);
            byte[] tokenForEndpoint = new byte[0];
            if (!serverGSSContext.getCredDelegState()) {
                logger.warn("credentials can not be delegated!");
                return null;
            } else {
                GSSCredential clientCred = serverGSSContext.getDelegCred();
                GSSName gssServerName = gssManager.createName(this.endpointSPN, GSSName.NT_USER_NAME);
                Oid kerberosMechOid = OID.KERBEROS5;
                GSSContext clientContext = gssManager.createContext(gssServerName.canonicalize(kerberosMechOid), kerberosMechOid, clientCred, 0);
                clientContext.requestCredDeleg(true);
                tokenForEndpoint = clientContext.initSecContext(tokenForEndpoint, 0, tokenForEndpoint.length);
                return new Pair(krbDetails, Base64.encodeBytes(tokenForEndpoint, 8));
            }
        } catch (GSSException var12) {
            logger.warn("Caught GSS Error", var12);
            return null;
        }
    }
}
