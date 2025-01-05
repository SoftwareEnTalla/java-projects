package cu.entalla.security;

import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class TrustSpecificHostsManager implements X509TrustManager,EnTallaTrustManager {

    // Mapa de hosts permitidos y sus certificados
    private final Map<String, Certificate> trustedHosts = new HashMap<>();


    private static final Logger logger = Logger.getLogger(TrustSpecificHostsManager.class.getName());
    public TrustSpecificHostsManager(Map<String, Certificate> trustedHosts) {
        this.trustedHosts.putAll(trustedHosts);
    }

    public EnTallaTrustManager addTrustedHosts(Map<String, Certificate> trustedHosts){
        this.trustedHosts.putAll(trustedHosts);
        return this;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("La cadena de certificados del cliente es nula o vacía.");
        }

        if (authType == null || authType.isEmpty()) {
            throw new CertificateException("El tipo de autenticación (authType) no está especificado.");
        }

        X509Certificate clientCert = chain[0]; // Usamos el primer certificado en la cadena
        boolean isTrusted = trustedHosts.values().stream()
                .anyMatch(trustedCert -> trustedCert.equals(clientCert));

        if (!isTrusted) {
            throw new CertificateException("El certificado del cliente no es de confianza.");
        }

        // Verifica que el certificado no esté expirado o revocado
        clientCert.checkValidity(); // Lanza CertificateExpiredException o CertificateNotYetValidException si el certificado no es válido
    }


    // Método para obtener una lista de hosts desde el certificado X.509
    private List<String> getHostsFromCertificate(X509Certificate cert) throws CertificateException {
        List<String> hosts = new ArrayList<>();

        // 1. Primero intentamos obtener el Common Name (CN) del sujeto del certificado
        String subjectDN = cert.getSubjectDN().getName();
        String cnHost = getCommonNameFromSubjectDN(subjectDN);
        if (cnHost != null && !cnHost.isEmpty()) {
            hosts.add(cnHost); // Si encontramos un CN válido, lo agregamos a la lista
        }

        // 2. Luego buscamos en los Subject Alternative Names (SAN)
        Collection<List<?>> sanList = cert.getSubjectAlternativeNames();
        if (sanList != null) {
            for (List<?> sanEntry : sanList) {
                Integer sanType = (Integer) sanEntry.get(0); // El primer elemento de la lista es el tipo de SAN
                String sanHost = (String) sanEntry.get(1);  // El segundo elemento es el valor del SAN
                // Aceptamos solo los SAN de tipo DNS (tipo 2)
                if (sanType == 2 && sanHost != null && !sanHost.isEmpty()) {
                    hosts.add(sanHost);
                }
            }
        }

        // Si no encontramos ningún host, lanzamos una excepción
        if (hosts.isEmpty()) {
            throw new CertificateException("No se pudo obtener el nombre del host del certificado.");
        }

        return hosts;
    }

    // Método auxiliar para extraer el Common Name (CN) de un Subject DN
    private String getCommonNameFromSubjectDN(String subjectDN) {
        // El DN tiene el formato "CN=nombre_del_host, O=Organización, ..."
        String[] dnComponents = subjectDN.split(",");
        for (String component : dnComponents) {
            if (component.trim().startsWith("CN=")) {
                return component.trim().substring(3); // Retorna el valor del CN sin "CN="
            }
        }
        return null; // Si no encuentra un CN, retorna null
    }


    @Override

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("La cadena de certificados es nula o vacía.");
        }

        X509Certificate serverCert = chain[0]; // Usamos el primer certificado de la cadena
        boolean isTrusted = trustedHosts.values().stream()
                .anyMatch(trustedCert -> trustedCert.equals(serverCert));

        if (!isTrusted) {
            throw new CertificateException("El certificado del servidor no es de confianza.");
        }

        if (serverCert instanceof X509Certificate) {
            X509Certificate x509Cert = (X509Certificate) serverCert;
            List<String> sanHosts=getHostsFromCertificate(x509Cert);
            // Añadir todos los hosts encontrados en sanHosts a trustedHosts si no están presentes
            sanHosts.forEach(host -> {
                trustedHosts.putIfAbsent(host, serverCert);  // Solo se agrega si no está ya presente
            });
        }
    }


    public X509Certificate[] getAcceptedIssuers() {

        return trustedHosts.values().stream()
                .filter(cert -> cert instanceof X509Certificate)
                .toArray(X509Certificate[]::new);
    }

    /**
     * Carga certificados desde un KeyStore y asocia un host específico.
     */
    public static Map<String, Certificate> loadTrustedHosts(KeyStore keyStore, Map<String, String> hostAliases) throws Exception {
        Map<String, Certificate> trustedHosts = new HashMap<>();
        logger.info("Loading trustedHosts from keyStore...");
        for (Map.Entry<String, String> entry : hostAliases.entrySet()) {
            String host = entry.getKey();
            String alias = entry.getValue();
            logger.info("Loading certificate of " + host + " with alias " + alias);
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate == null) {
                logger.warning("Alias no encontrado en el KeyStore: " + alias);
                continue;
            }

            // Analizar SAN del certificado si es X509Certificate
            if (certificate instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) certificate;
                Collection<List<?>> sanList = x509Cert.getSubjectAlternativeNames();
                if (sanList != null) {
                    for (List<?> sanEntry : sanList) {
                        String sanHost = (String) sanEntry.get(1);
                        logger.info("Adicionando SAN host: " + sanHost);
                        trustedHosts.put(sanHost, certificate);
                    }
                }
            }

            trustedHosts.put(host, certificate);
        }

        return trustedHosts;
    }

    public List<String> getAllTrustedHost(){
        return trustedHosts.keySet().stream().collect(Collectors.toList());
    }

}
