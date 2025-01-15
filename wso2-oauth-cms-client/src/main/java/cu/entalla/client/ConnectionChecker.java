package cu.entalla.client;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import cu.entalla.model.JwkKey;
import cu.entalla.security.TrustAnyTrustManager;
import cu.entalla.service.JwksProcessorService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ConnectionChecker {

    static {
        // Configuración para ignorar validaciones SSL
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }}, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Ignorar validación de nombres de host
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean isUriReachable(String issuerUri) {
        try {
            URL url = new URL(issuerUri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();
            int responseCode = connection.getResponseCode();
            return responseCode >= 200 && responseCode < 300;
        } catch (Exception e) {
            System.err.println("Error verificando conexión HTTPS: " + e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene la clave pública desde un recurso JWKS publicado en el servidor.
     *
     * @param keyId El ID de la clave (kid) que se desea obtener del JWKS.
     * @return Clave pública como un objeto RSAPublicKey.
     * @throws Exception Si ocurre un error al leer o procesar el JWKS.
     */
    public static RSAPublicKey getPublicKeyFromJWKS(String url, String keyId) throws Exception {
        // Obtén el objeto JwksProcessorService desde la URL
        JwksProcessorService jwksProcessorService = JwksProcessorService.fromUrl(url);

        // Busca la clave pública en la lista de claves por el ID
        JwkKey jwkKey = jwksProcessorService.getKeys().stream()
                .filter(key -> key.getKeyId().equals(keyId))  // Filtra por el keyId
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No se encontró una clave con el ID: " + keyId));

        // Aquí se puede agregar la lógica para convertir el JwkKey a una clave pública RSA
        if (jwkKey.getKeyType().equals("RSA")) {
            // Asume que el JwkKey contiene información suficiente para generar la clave pública
            // Aquí deberías agregar el código para convertir el JwkKey en una RSAPublicKey
            return jwkKey.toRSAPublicKey();  // Método que implementes para convertir el JwkKey a RSAPublicKey
        } else {
            throw new IllegalArgumentException("La clave con el ID proporcionado no es una clave RSA.");
        }
    }
    public static RSAPublicKey getPublicKeyFromJWKS(String url) throws Exception {
        // Obtén el objeto JwksProcessorService desde la URL
        JwksProcessorService jwksProcessorService = JwksProcessorService.fromUrl(url);

        // Busca la clave pública en la lista de claves por el ID
        JwkKey jwkKey = jwksProcessorService.getKeys().stream()
                .filter(key -> key.getKeyId()!=null)  // Filtra por el keyId
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No se encontraron claves en la url: " + url));

        // Aquí se puede agregar la lógica para convertir el JwkKey a una clave pública RSA
        if (jwkKey.getKeyType().equals("RSA")) {
            // Asume que el JwkKey contiene información suficiente para generar la clave pública
            // Aquí deberías agregar el código para convertir el JwkKey en una RSAPublicKey
            return jwkKey.toRSAPublicKey();  // Método que implementes para convertir el JwkKey a RSAPublicKey
        } else {
            throw new IllegalArgumentException("La clave con el ID proporcionado no es una clave RSA.");
        }
    }
    public static List<JwkKey> getJwkKeysFromJWKS(String url) throws Exception {
        // Obtén el objeto JwksProcessorService desde la URL
        JwksProcessorService jwksProcessorService = JwksProcessorService.fromUrl(url);

        // Busca la clave pública en la lista de claves por el ID
        return jwksProcessorService.getKeys().stream()
                .filter(key -> key.getKeyId() != null).collect(Collectors.toList());

    }
    public static ConnectionResult getConnectionResult(String issuerUri) {
        try {
            // Crear el objeto URL
            URL url = new URL(issuerUri);
            // Si la URL es HTTPS, usar HttpsURLConnection
            HttpURLConnection connection;
            if ("https".equalsIgnoreCase(url.getProtocol())) {
                // Configurar para ignorar la validación SSL
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{new TrustAnyTrustManager()}, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
                // Ignorar validación de nombre de host
                HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
                connection = (HttpsURLConnection) url.openConnection();  // Usar HttpsURLConnection
            } else {
                connection = (HttpURLConnection) url.openConnection();  // Usar HttpURLConnection para HTTP
            }

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);  // Tiempo de espera de conexión
            connection.setReadTimeout(5000);    // Tiempo de espera de lectura
            connection.connect();
            int code=connection.getResponseCode();
            // Leer el cuerpo de la respuesta (responseText)
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder responseText = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                responseText.append(inputLine);
            }
            in.close();
            return new ConnectionResult(code,responseText);
        } catch (Exception e) {
            System.err.println("Error verificando conexión HTTPS: " + e.getMessage());
            return null;
        }
    }

    @Getter
    @AllArgsConstructor
    public static class ConnectionResult {
        private  int responseCode;
        private  Object response;

        public boolean isOk(){
            return responseCode >= 200 && responseCode < 300;
        }

        @Override
        public String toString() {
            return "Code: " + responseCode + ", Response: " + response;
        }
    }

}


