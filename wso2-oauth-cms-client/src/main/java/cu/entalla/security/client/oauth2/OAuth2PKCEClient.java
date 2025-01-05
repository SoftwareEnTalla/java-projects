package cu.entalla.security.client.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.security.TrustAnyTrustManager;
import cu.entalla.store.AuthenticationStore;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import javax.net.ssl.*;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.*;
import java.util.logging.Logger;

@Getter
public class OAuth2PKCEClient {

    private Wso2SecurityConfig config;
    private HttpServletRequest httpRequest;
    private static final Logger logger = Logger.getLogger(OAuth2PKCEClient.class.getName());
    public OAuth2PKCEClient(Wso2SecurityConfig config){
        this.config=config;
    }
    public OAuth2PKCEClient(Wso2SecurityConfig config,HttpServletRequest httpRequest){
        this.config=config;
        this.httpRequest=httpRequest;
    }
    public String getAuthorizationCode(Object savedCodeVerifier)
            throws IOException, InterruptedException, NoSuchAlgorithmException, KeyManagementException {
        if(config==null)
            config=AuthenticationStore.getInstance().getWso2SecurityConfig();
        ClientRegistration registry = config.clientRegistrationRepository().findByRegistrationId("wso2");
        logger.info("ClientRegistration Loaded: " + (registry!=null));

        // Endpoint de PAR
        String parEndpoint = config.getParUri();
        logger.info("PAR ENDPOINT: " + parEndpoint);

        // Endpoint de PAR
        String authorizedEndpoint = config.getAuthorizationUri();
        logger.info("PAR ENDPOINT: " + parEndpoint);

        // Generar Code Verifier
        String codeVerifier =savedCodeVerifier!=null?savedCodeVerifier.toString(): config.generateCodeVerifier();
        if(httpRequest!=null)
          httpRequest.getSession().setAttribute("code_verifier",codeVerifier);
        logger.info("codeVerifier: " + codeVerifier);

        // Generar Code Challenge
        String codeChallenge = config.generateCodeChallenge(codeVerifier);
        logger.info("codeVerifier: " + codeVerifier);

        // Construir parámetros del cuerpo de la solicitud
        StringJoiner params = new StringJoiner("&");
        params.add("client_id=" + URLEncoder.encode(registry.getClientId(), StandardCharsets.UTF_8));
        params.add("response_type=code");
        params.add("redirect_uri=" + URLEncoder.encode(registry.getRedirectUri(), StandardCharsets.UTF_8));
        params.add("code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8));
        params.add("code_challenge_method=S256");
        params.add("scope=" + URLEncoder.encode(String.join(" ", registry.getScopes()), StandardCharsets.UTF_8));
        logger.info("PARAMS: " + params.toString());

        // Configurar SSLContext que confía en todos los certificados
        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager trustManager = AuthenticationStore.getInstance().getTrustManager();
        sslContext.init(null, new TrustManager[]{new TrustAnyTrustManager(),trustManager}, new java.security.SecureRandom());
        logger.info("SSLCONTEXT inicialized..." );
        // Configurar HostnameVerifier que confía en todos los hosts
        HostnameVerifier allHostsValid = (hostname, session) -> true;
        logger.info("HostNameVerifier..." );
        // Crear HttpClient con el SSLContext y HostnameVerifier personalizados
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(new SSLParameters()) // Opcional, mejora compatibilidad
                .build();
        logger.info("HttpClient created..." );
        // Construir la solicitud HTTP POST
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(authorizedEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .build();
        logger.info("Request to:"+authorizedEndpoint );
        // Enviar la solicitud y capturar la respuesta
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        logger.info("STATUS CODE:"+response.statusCode());
        logger.info("RESPUESTA SIN PROCESAR:"+response.body());
        // Verificar que el código de estado sea exitoso (200-299)
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            // Parsear el cuerpo de la respuesta JSON
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> responseBody = objectMapper.readValue(response.body(), Map.class);

            // Verificar si contiene "request_uri"
            if (responseBody.containsKey("request_uri")) {
                logger.info("REQUEST_URI CON PAR: " + responseBody.get("request_uri").toString());
                return responseBody.get("request_uri").toString();
            } else {
                throw new IOException("La respuesta no contiene el campo 'request_uri'.");
            }
        } else {
            throw new IOException("Error en la solicitud a la Url: " +authorizedEndpoint+" con status code:"+ response.statusCode() + " y response: " + response.body());
        }
    }

    public String authenticate() throws Exception {

        // Paso 1: Generar el JWT para client_assertion
        PrivateKey privateKey = loadPrivateKeyFromPem(config.getPrivateKeyPath());
        String jwt = createJWT(privateKey);
        logger.info("JWT generado:"+jwt);

        // Paso 2: Obtener el Authorization Code desde el navegador o proceso PKCE
        Object codeVerifier=httpRequest.getSession().getAttribute("code_verifier");
        String authorizationCode = getAuthorizationCode(codeVerifier);
        logger.info("AuthorizationCode: " + authorizationCode);
        // Paso 3: Hacer la solicitud POST al endpoint /oauth2/token
        String tokenEndpoint = config.getTokenUri();
        String redirectUri = config.getRedirectUri();
        logger.info("TokenEndpoint: " + tokenEndpoint);
        logger.info("RedirectUri: " + redirectUri);

        String requestBody = "grant_type=authorization_code"
                + "&code=" + authorizationCode
                + "&redirect_uri=" + redirectUri
                + "&client_assertion=" + jwt
                + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        logger.info("RequestAccessTokenBody: " + requestBody);
        String response = sendPostRequest(tokenEndpoint, requestBody);
        logger.info("Respuesta del servidor: " + response);
        return response;
    }
    public String authenticate(Object codeVerifier) throws Exception {

        // Paso 1: Generar el JWT para client_assertion
        PrivateKey privateKey = loadPrivateKeyFromPem(config.getPrivateKeyPath());
        String jwt = createJWT(privateKey);
        logger.info("JWT generado:"+jwt);

        // Paso 2: Obtener el Authorization Code desde el navegador o proceso PKCE
        String authorizationCode = getAuthorizationCode(codeVerifier);
        logger.info("AuthorizationCode: " + authorizationCode);
        // Paso 3: Hacer la solicitud POST al endpoint /oauth2/token
        String tokenEndpoint = config.getTokenUri();
        String redirectUri = config.getRedirectUri();
        logger.info("TokenEndpoint: " + tokenEndpoint);
        logger.info("RedirectUri: " + redirectUri);

        String requestBody = "grant_type=authorization_code"
                + "&code=" + authorizationCode
                + "&redirect_uri=" + redirectUri
                + "&client_assertion=" + jwt
                + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        logger.info("RequestAccessTokenBody: " + requestBody);
        String response = sendPostRequest(tokenEndpoint, requestBody);
        logger.info("Respuesta del servidor: " + response);
        return response;
    }

    private String sendPostRequest(String endpoint, String body) throws Exception {
        // Configurar SSLContext que confía en todos los certificados
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{AuthenticationStore.getInstance().getTrustManager()}, new java.security.SecureRandom());
        // Configurar HostnameVerifier que confía en todos los hosts
        HostnameVerifier allHostsValid = (hostname, session) -> true;
        logger.info("SSL_CONTEXT and HostnameVerifier loaded...");

        URL url = new URL(endpoint);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setHostnameVerifier(allHostsValid);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setDoOutput(true);
        logger.info("HttpsURLConnection inicialized...");
        // Enviar el cuerpo del request
        try (OutputStream os = connection.getOutputStream()) {
            logger.info("Sending request...");
            os.write(body.getBytes());
            os.flush();
        }

        // Leer la respuesta
        int responseCode = connection.getResponseCode();
        logger.info("Response Code :"+responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) {
            return new String(connection.getInputStream().readAllBytes());
        } else {
            logger.info("Error en la solicitud: Código " + responseCode);
            throw new RuntimeException("Error en la solicitud: Código " + responseCode);
        }
    }

    private PrivateKey loadPrivateKeyFromPem(String filePath) throws Exception {
        logger.info("Load private key from:" + filePath);
        try (Reader reader = new FileReader(filePath);
             PEMParser pemParser = new PEMParser(reader)) {
             logger.info("PEMParser creado satisfactoriamente desde:" + filePath);
            // Leer el objeto desde el archivo
            Object pemObject = pemParser.readObject();
            logger.info("PemObject creado satisfactoriamente desde:" + filePath);
            // Convertir el objeto a PrivateKeyInfo
            if (pemObject instanceof PrivateKeyInfo) {
                logger.info("PemObject es instancia de :PrivateKeyInfo");
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemObject;
                logger.info("PemObject es convertido a :PrivateKeyInfo");
                // Convertir PrivateKeyInfo a PrivateKey
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                logger.info("JcaPEMKeyConverter es creado para retornar llave privada");
                return converter.getPrivateKey(privateKeyInfo);
            } else {
                logger.info("PemObject no es instancia de :PrivateKeyInfo");
                throw new IllegalArgumentException("El archivo PEM no contiene una clave privada válida.");
            }
        }

    }

    private boolean isValidBase64(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String extractBase64Content(String pem) {
        // Filtrar líneas que no sean parte del contenido Base64
        return pem.lines()
                .filter(line -> !(line.startsWith("-----") || line.startsWith("BagAttributes") || line.startsWith("KeyAttributes") || line.isEmpty()))
                .reduce("", (acc, line) -> acc + line);
    }


    private String createJWT(PrivateKey privateKey) {
        return Jwts.builder()
                .setIssuer(config.getClientId())
                .setSubject(config.getClientId())
                .setAudience(config.getTokenUri())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hora
                .setIssuedAt(new Date())
                .setId(UUID.randomUUID().toString())
                .signWith(SignatureAlgorithm.RS256,privateKey )
                .compact();
    }
}
