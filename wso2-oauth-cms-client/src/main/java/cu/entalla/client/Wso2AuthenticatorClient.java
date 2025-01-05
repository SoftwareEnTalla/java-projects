package cu.entalla.client;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.model.AuthorizationRequestModel;
import cu.entalla.model.AuthorizationResponseModel;
import cu.entalla.model.OpenIDConfiguration;
import cu.entalla.model.TokenResponseModel;
import cu.entalla.security.EnTallaTrustManager;
import cu.entalla.security.TrustAnyTrustManager;
import cu.entalla.security.TrustSpecificHostsManager;
import cu.entalla.service.AuthenticationService;
import cu.entalla.store.AuthenticationStore;
import lombok.Getter;
import org.json.JSONObject;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import javax.net.ssl.*;
import java.awt.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Getter
public class Wso2AuthenticatorClient {

    private HttpClient httpClient;
    private static Wso2AuthenticatorClient _instance;
    private static final Logger logger = Logger.getLogger(Wso2AuthenticatorClient.class.getName());

    private SSLContext sslContext;
    private HostnameVerifier hostnameVerifier;
    private static EnTallaTrustManager trustManager=null;

    // CompletableFuture para esperar el resultado del callback
    private static final CompletableFuture<AuthorizationResponseModel> callbackResponse = new CompletableFuture<>();

    private Wso2AuthenticatorClient(SSLContext sslContext, HostnameVerifier hostnameVerifier) {
        this.sslContext=sslContext;
        this.hostnameVerifier=hostnameVerifier;
        this.httpClient = getHttpClient();
        if(_instance==null)
            _instance=this;
    }
    public static Wso2AuthenticatorClient getInstance(){
        if(_instance==null){
            try {
                // Obtener el valor de CATALINA_BASE
                String catalinaBase = System.getenv("CATALINA_BASE");
                if(catalinaBase==null) {
                    catalinaBase = "/media/datos/Instaladores/entalla/tomcat";
                    System.setProperty("CATALINA_BASE",catalinaBase);
                }
                if(catalinaBase!=null)
                {
                    _instance = Wso2AuthenticatorClient.create(catalinaBase+"/shared/classes/alfresco-global.properties");
                    AuthenticationService authService=new AuthenticationService(_instance);
                    authService.authenticationWithCodeFlow("wso2");
                    //System.out.println("AuthorizationCode: " + code);
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return _instance;
    }
    public String getAuthorizationCode(){
        String response=null;
        try {
            AuthorizationRequestModel requestModel=new AuthorizationRequestModel();
            String url=requestModel.buildAuthorizeUrl();
            logger.info("Sending url for getAuthorizationCode:"+url);
            response=handleAuthorizationCodeRequest(url);

        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
        return response;
    }
    public String getAuthorizationCode(String Id){
        String response=null;
        try {
            AuthorizationRequestModel requestModel=new AuthorizationRequestModel();
            String url=requestModel.buildAuthorizeUrl(Id);
            logger.info("Sending url for getAuthorizationCode:"+url);
            response=handleAuthorizationCodeRequest(url);

        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
        return response;
    }

    public String handleAuthorizationCodeRequest(String authorizationUri) throws URISyntaxException, IOException, ExecutionException, InterruptedException {
        // Abrir el navegador
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(new URI(authorizationUri));
        } else {
            logger.info("Por favor, abre esta URL en tu navegador: " + authorizationUri);
        }
        // Esperar a que el callback complete la operación
        logger.info("Esperando el código de autorización desde el callback...");
        AuthorizationResponseModel model = callbackResponse.get(); // Bloquea hasta que se complete
        logger.info("Código de autorización recibido: " + model.getCode());
        logger.info("Datos adicionales recibidos: " + model.toJson());
        return model.getCode();
    }

    // Método para completar la operación desde el servlet
    public AuthorizationResponseModel completeCallback(String code, String session_state) {
        AuthorizationResponseModel model = AuthorizationResponseModel.builder().code(code).sessionState(session_state).build();
        logger.info("AuthorizationResponseModel builded with code="+code+" and sessionState="+session_state);
        boolean completed= callbackResponse.complete(model);
        logger.info("CallbackResponse="+completed);
        return model;
    }
    public String refreshAccessToken(String refreshToken) {
        Wso2SecurityConfig.create();
        Wso2SecurityConfig wso2SecurityConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
        String tokenEndpoint = wso2SecurityConfig.getTokenUri();  // Endpoint de token
        String clientId = wso2SecurityConfig.getClientId();  // Tu client_id
        String clientSecret = wso2SecurityConfig.getClientSecret();  // Tu client_secret

        try {
            // Codificar las credenciales en Base64 para la autenticación básica
            String credentials = clientId + ":" + clientSecret;
            String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
            logger.info("Credenciales codificadas: " + encodedCredentials);

            // Crear cuerpo de la solicitud con el refresh_token
            String body = "grant_type=refresh_token&refresh_token=" + refreshToken;

            // Crear cliente HTTP
           // HttpClient httpClient = HttpClient.newHttpClient();

            // Crear la solicitud POST para obtener un nuevo access_token
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + encodedCredentials) // Autenticación básica
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            // Enviar solicitud y manejar la respuesta
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Verificar el código de respuesta
            if (response.statusCode() == 200) {
                logger.info("Nuevo access_token recibido: " + response.body());
                // Aquí puedes parsear la respuesta para extraer el nuevo access_token
                return response.body();  // Retorna el cuerpo de la respuesta (puedes extraer solo el access_token)
            } else {
                System.err.println("Error al obtener el nuevo access_token: " + response.body());
                return null;
            }

        } catch (Exception e) {
            System.err.println("Error durante la solicitud de refresh_token: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    public boolean isJwtValidToken(String token){
        return true;
    }
    public boolean isValidToken(String token) {
        logger.info("Iniciando validación del token...");

        // Verificar que el token no sea nulo o vacío
        if (token == null || token.isEmpty()) {
            logger.severe("El token es nulo o vacío.");
            return false;
        }

        // Obtener configuración de WSO2
        Wso2SecurityConfig config = AuthenticationStore.getInstance().getWso2SecurityConfig();
        String introspectUri = config.getInstrospec();
        String clientId = config.getClientId();
        String clientSecret = config.getClientSecret();

        // Verificar configuración requerida
        if (introspectUri == null || clientId == null || clientSecret == null) {
            logger.severe("La configuración del endpoint de introspección o credenciales no está completa.");
            return false;
        }

        // Preparar la autenticación básica
        String credentials = clientId + ":" + clientSecret;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

        try {
            // Crear cuerpo de la solicitud con el token
            String body = "token=" + token + "&token_type_hint=access_token";

            // Crear cliente HTTP
            //HttpClient httpClient = HttpClient.newHttpClient();

            // Crear solicitud POST para el endpoint de introspección
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(introspectUri))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + encodedCredentials)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            // Enviar solicitud y manejar la respuesta
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            logger.info("Código de respuesta: " + response.statusCode());
            logger.info("Cuerpo de la respuesta: " + response.body());

            // Validar código de respuesta
            if (response.statusCode() != 200) {
                logger.severe("Error en la validación del token. Código de respuesta: " + response.statusCode());
                return false;
            }

            // Analizar la respuesta JSON
            JSONObject jsonResponse = new JSONObject(response.body());

            // Validar si el token está activo
            boolean isActive = jsonResponse.optBoolean("active", false);

            if (isActive) {
                logger.info("El token es válido.");
                // Registrar detalles adicionales si están disponibles
                logger.info("Usuario asociado: " + jsonResponse.optString("username", "N/A"));
                logger.info("Scopes: " + jsonResponse.optString("scope", "N/A"));
                logger.info("Cliente: " + jsonResponse.optString("client_id", "N/A"));
            } else {
                logger.warning("El token no está activo.");
            }

            return isActive;

        } catch (Exception e) {
            logger.severe("Error durante la validación del token: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public String getAccessToken(String code) throws Exception {
        logger.info("getAccessToken...");
        if (!AuthenticationStore.getInstance().hasClientRegistrationRepository()) {
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }

        // Obtén el registro del cliente
        ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
        logger.info("clientRegistration: " + clientRegistration);

        // Construye el cuerpo de la solicitud
        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
        String body = String.format(
                "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(clientRegistration.getRedirectUri(), StandardCharsets.UTF_8),
                URLEncoder.encode(clientRegistration.getClientId(), StandardCharsets.UTF_8),
                URLEncoder.encode(clientRegistration.getClientSecret(), StandardCharsets.UTF_8)
        );

        // Crea la solicitud POST
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        // Envía la solicitud
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        logger.info("Response: " + response.body());

        // Maneja la respuesta
        if (response.statusCode() != 200) {
            throw new RuntimeException("Error al obtener el token: " + response.body());
        }

        // Extrae el access_token
        JSONObject jsonResponse = new JSONObject(response.body());
        if (!jsonResponse.has("access_token")) {
            throw new RuntimeException("El servidor no devolvió un access_token.");
        }
        String accessToken = jsonResponse.getString("access_token");
        logger.info("AccessToken: " + accessToken);
        return accessToken;
    }

    public String getAccessToken(String code, String codeVerifier) throws Exception {
        logger.info("getAccessToken using PKCE...");

        if (!AuthenticationStore.getInstance().hasClientRegistrationRepository()) {
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }

        // Obtén el registro del cliente
        ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
        logger.info("clientRegistration: " + clientRegistration);

        // Construye el cuerpo de la solicitud
        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
        String body = String.format(
                "grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(clientRegistration.getRedirectUri(), StandardCharsets.UTF_8),
                URLEncoder.encode(clientRegistration.getClientId(), StandardCharsets.UTF_8),
                URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8)
        );

        // Crea la solicitud POST
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        // Envía la solicitud
        HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        String responseText=response.body();
        logger.info("Response: " + responseText);

        // Maneja la respuesta
        if (response.statusCode() != 200) {
            throw new RuntimeException("Error al obtener el token: " + responseText);
        }

        // Extrae el access_token
        JSONObject jsonResponse = new JSONObject(responseText);
        if (!jsonResponse.has("access_token")) {
            throw new RuntimeException("El servidor no devolvió un access_token.");
        }
        AuthenticationStore.getInstance().setTokenModel(TokenResponseModel.fromJson(jsonResponse));
        String accessToken = jsonResponse.getString("access_token");
        logger.info("AccessToken: " + accessToken);
        return accessToken;
    }

    private String basicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    public HttpClient getHttpClient(){
        if(httpClient==null){
            HttpClient.Builder builder = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .sslParameters(new SSLParameters() {{
                        setEndpointIdentificationAlgorithm("HTTPS");
                    }})
                    .followRedirects(HttpClient.Redirect.ALWAYS) // Seguir redirecciones automáticamente
                    .version(HttpClient.Version.HTTP_2);

            if (hostnameVerifier != null) {
                builder = builder.sslParameters(new SSLParameters() {
                    @Override
                    public void setEndpointIdentificationAlgorithm(String algorithm) {
                        super.setEndpointIdentificationAlgorithm("HTTPS");
                    }
                });
            }
            httpClient=builder.build();
        }
        return httpClient;
    }
    public String sendGetRequest(String url) throws IOException, InterruptedException {

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        // Imprimir el código de estado
        logger.info("Código de estado: " + response.statusCode());
        // Imprimir el cuerpo o la redirección final
        if (response.statusCode() == 302) {
            logger.info("Redirigido a: " + response.headers().firstValue("Location").orElse("No location header found"));
        } else {
            logger.info("Respuesta del servidor: " + response.body());
        }
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return response.body();
        } else {
            throw new IOException("Request failed with status code: " + response.statusCode());
        }
    }

    // HostnameVerifier personalizado
    private static HostnameVerifier createCustomHostnameVerifier(List<String> trustedHosts) {
        return (hostname, session) -> {
            try {
                Certificate[] certs = session.getPeerCertificates();
                if (certs.length == 0) {
                    return false;
                }

                X509Certificate serverCert = (X509Certificate) certs[0];
                Collection<List<?>> serverAltNames = serverCert.getSubjectAlternativeNames();

                if (serverAltNames == null) {
                    return false;
                }

                // Extraer SANs del servidor
                List<String> serverSans = serverAltNames.stream()
                        .filter(name -> name.get(1) instanceof String)
                        .map(name -> (String) name.get(1))
                        .collect(Collectors.toList());

                // Verificar si el hostname está en los SANs del servidor
                boolean serverTrusted = serverSans.contains(hostname);

                // Verificar si el hostname está en la lista de hosts de confianza
                boolean clientTrusted = trustedHosts.contains(hostname);

                return serverTrusted && clientTrusted;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        };
    }
    // SSLContext confiable
    private static SSLContext createTrustAllSSLContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new TrustAnyTrustManager()}, null);

            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }
    }

    private static EnTallaTrustManager loadHostManager(String trustStoreFilePath,String trustStorePass,String keyStoreType) throws KeyStoreException, FileNotFoundException {

        if(new File(trustStoreFilePath).exists()){
            // Configurar los hosts permitidos y sus alias en el KeyStore
            Map<String, String> hostAliases = new HashMap<>();
            hostAliases.put("ses-idp.entalla.cu", "ses-idp.entalla.cu");
            hostAliases.put("ses-cms.entalla.cu", "ssl.repo");
            logger.info("Los HostAliases han sido inicializados con "+hostAliases.size()+" elementos...");
            // Cargar el KeyStore
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            logger.info("Abriendo "+trustStoreFilePath+" para carga inicial...");
            try (FileInputStream fis = new FileInputStream(trustStoreFilePath)) {
                keyStore.load(fis, trustStorePass.toCharArray());
                logger.info("KeyStore cargado desde "+trustStoreFilePath+" satisfactoriamente...");
                // Crear el mapa de hosts confiables
                logger.info("Iniciando trustedHosts con los hostAliases...");
                Map<String, Certificate> trustedHosts = TrustSpecificHostsManager.loadTrustedHosts(keyStore, hostAliases);

                // Crear el TrustManager personalizado
                if(trustManager==null){
                    logger.info("Iniciando trustManager con los trustedHosts...");
                    trustManager =  new TrustSpecificHostsManager(trustedHosts);
                }
                else {
                    logger.info("Adicionando  trustedHosts al  trustManager ya iniciado...");
                    trustManager=trustManager.addTrustedHosts(trustedHosts);
                }

            } catch (CertificateException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (IOException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            } catch (Exception e) {
                logger.severe(e.getMessage());
                throw new RuntimeException(e);
            }
        }
        return trustManager;
    }
    private  static SSLContext createTrustSpecificSSLContext(String configFilePath) {
        logger.info("Cargando configuración desde: " + configFilePath);
        Wso2SecurityConfig wso2SecConfig =AuthenticationStore.getInstance().getWso2SecurityConfig()==null? new Wso2SecurityConfig(configFilePath):AuthenticationStore.getInstance().getWso2SecurityConfig();

        try {
            if(!wso2SecConfig.isLoaded())
                wso2SecConfig.loadProperties();
            AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecConfig);
            String tomcatTrustStoreFilePath =  wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.location",null);
            String tomcatTrustStorePass = wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.password",null);
            String keyStoreType = wso2SecConfig.getPropertyByKey("ssl.tomcat.keystore.type", "JCEKS");
            logger.info("Cargando certificados de confianza de tomcat:"+tomcatTrustStoreFilePath);
            if(tomcatTrustStoreFilePath!=null && tomcatTrustStorePass!=null)
                loadHostManager(tomcatTrustStoreFilePath,tomcatTrustStorePass,keyStoreType);

            String wso2isTrustStoreFilePath =  wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.location",null);
            String wso2isTrustStorePass = wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.password",null);
            keyStoreType = wso2SecConfig.getPropertyByKey("ssl.wso2is.keystore.type", "JKS");
            logger.info("Cargando certificados de confianza de wso2is:"+wso2isTrustStoreFilePath);
            if(wso2isTrustStoreFilePath!=null && wso2isTrustStorePass!=null)
                loadHostManager(wso2isTrustStoreFilePath,wso2isTrustStorePass,keyStoreType);

        } catch (KeyStoreException ke) {
            ke.fillInStackTrace();
            throw new RuntimeException(ke);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecConfig);
        if(trustManager!=null){
            AuthenticationStore.getInstance().setTrustManager(trustManager);
        }
        try {

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustManager}, null);
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }

    }
    public static String discoverOidcEndPoints(String propertyFilePath){
        String url=null;
        String response=null;
        try {
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(propertyFilePath);
            OpenIDConfiguration conf=AuthenticationStore.getInstance().getOpenIdConfiguration();
            if(conf!=null){
                url = conf.getTokenEndpoint()+ "/.well-known/openid-configuration";
                response= conf.toJson();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
    public static Wso2AuthenticatorClient create(String propertyFilePath){
        try {
            // Configuración
           SSLContext sslContext = createTrustSpecificSSLContext(propertyFilePath);// createTrustAllSSLContext();
            List<String> trustedHosts = new ArrayList<>();
            trustedHosts.add("localhost");
            TrustManager trustManager = AuthenticationStore.getInstance().getTrustManager();
            if(trustManager instanceof  TrustSpecificHostsManager){
                ((TrustSpecificHostsManager)trustManager).getAllTrustedHost().forEach(item -> {
                    // Si el item no existe en list1, lo agrega
                    if (!trustedHosts.contains(item)) {
                        trustedHosts.add(item);
                    }
                });
            }
            //trustedHosts.add("ses-idp.entalla.cu");
           HostnameVerifier hostnameVerifier = createCustomHostnameVerifier(trustedHosts);
            Wso2AuthenticatorClient client= new Wso2AuthenticatorClient(sslContext, hostnameVerifier);
            return client;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static void main(String[] args) {
        try {

            String catalinaBase = System.getenv("CATALINA_BASE");
            if(catalinaBase==null) {
                catalinaBase = "/media/datos/Instaladores/entalla/tomcat";
                System.setProperty("CATALINA_BASE",catalinaBase);
            }
            logger.info("CATALINA_BASE ON OAuth2CallbackServlet="+catalinaBase);
            if(catalinaBase!=null){
                catalinaBase+=(catalinaBase.endsWith("/")?"":"/");
                String configFilePath = catalinaBase + "shared/classes/alfresco-global.properties";
                logger.info("WSO2_CONFIG_FILE="+configFilePath);
                Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(configFilePath);
                AuthenticationService authService=new AuthenticationService(client);
                String accessToken="eyJ4NXQiOiJZVEpsTTJabE56RXlZbU5rTXpsbE1ERmtNbVE0WWpRek9EVTBOVFZpWm1NeU1qUXhaREV3WWpZeU5qazFNalpqT0dSa01XTmxPVEEwWkdRellUQTNOdyIsImtpZCI6IllUSmxNMlpsTnpFeVltTmtNemxsTURGa01tUTRZalF6T0RVME5UVmlabU15TWpReFpERXdZall5TmprMU1qWmpPR1JrTVdObE9UQTBaR1F6WVRBM053X1JTMjU2IiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI4MGYwMGI1Yy0wYmEyLTQ1NzItOTU3YS1hOTY3ODI5OTlmMDYiLCJhdXQiOiJBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoic3NvLXNlc3Npb24iLCJpc3MiOiJodHRwczpcL1wvc2VzLWlkcC5lbnRhbGxhLmN1Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJnaXZlbl9uYW1lIjoiUGVyc3kiLCJjbGllbnRfaWQiOiJGQTZVQW9iZDJFeFkyaHVhZzVDSUJhendHWjBhIiwiYXVkIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm5iZiI6MTczNTA1MDM5MiwiYXpwIjoiRkE2VUFvYmQyRXhZMmh1YWc1Q0lCYXp3R1owYSIsIm9yZ19pZCI6IjEwMDg0YThkLTExM2YtNDIxMS1hMGQ1LWVmZTM2YjA4MjIxMSIsInNjb3BlIjoiZW1haWwgb3BlbmlkIHBob25lIHByb2ZpbGUiLCJwaG9uZV9udW1iZXIiOiIrNTMgNTMzNjQ2NTQiLCJleHAiOjE3MzUwNTM5OTIsIm9yZ19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MzUwNTAzOTIsImZhbWlseV9uYW1lIjoiTW9yZWxsIEd1ZXJyYSIsImJpbmRpbmdfcmVmIjoiYjE0YjI5YTY4ZjVjNDEwNWU2M2IxNTcxODk5NjIxNTciLCJqdGkiOiI3ZGE0NjEwNi03Mzc4LTRmNDItYjQyOS05OWNjZjI0NGU1MmYiLCJlbWFpbCI6InBtb3JlbGxAeGV0aWQuY3UiLCJ1c2VybmFtZSI6ImFkbWluIn0.cUFKTJYIg5PF2MWbBXodGpMfhAlcsVlEy9lXT9IY-KnVSfyWTY8DZrHkVyX29ZRpxK8o1GpciKh_AWksiSgXbDjbR2deT8Wjwgg4MvgGNuk1NJZJN8lSgOSmmSvOZSF9-L46Sj0iVqNM4BfbjuOiknXhJ08KKpZ4bpWG4zww3GhOnIxScIvmsm0lfjgtqxKXC8Me8nFy30b9TSe7-de22tHiazOnNtX79TTzIREmQWh96EFB4OSx1N6isf2AdNHjl8NO42GzDELYVEql0SZcGrEltAAUqAj7WMOx2JCHsE03IIlGv422iXAy6xfDzKP-5Lxts8jnpZ4MpB1lccQEkw";
                boolean valid= authService.isValidToken(accessToken);

                Wso2SecurityConfig tmp=AuthenticationStore.getInstance().getWso2SecurityConfig();
                Wso2SecurityConfig wso2SecurityConfig = tmp.loadProperties();
                AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecurityConfig);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
