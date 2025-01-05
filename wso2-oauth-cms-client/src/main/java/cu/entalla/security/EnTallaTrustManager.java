package cu.entalla.security;

import javax.net.ssl.TrustManager;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public interface EnTallaTrustManager extends TrustManager {
    public EnTallaTrustManager addTrustedHosts(Map<String, Certificate> trustedHosts);
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException;
}
