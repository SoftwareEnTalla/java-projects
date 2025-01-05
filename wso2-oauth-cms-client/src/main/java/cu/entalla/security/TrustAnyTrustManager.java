package cu.entalla.security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TrustAnyTrustManager implements X509TrustManager,EnTallaTrustManager {

    private final Map<String, Certificate> trustedHosts = new HashMap<>();
    private static final Logger logger = Logger.getLogger(TrustAnyTrustManager.class.getName());

    public TrustAnyTrustManager(Map<String, Certificate> trustedHosts) {
        this.trustedHosts.putAll(trustedHosts);
    }
    public TrustAnyTrustManager() {

    }
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public EnTallaTrustManager addTrustedHosts(Map<String, Certificate> trustedHosts){
        this.trustedHosts.putAll(trustedHosts);
        return this;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}