package cu.entalla.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.exception.EmptyOidcEndPointException;
import cu.entalla.exception.EmptyOpenIdConfigurationException;
import cu.entalla.exception.EmptyWso2AuthenticatorClient;
import cu.entalla.exception.EnTallaFileNotExistException;
import cu.entalla.model.AuthorizationRequestModel;
import cu.entalla.model.OpenIDConfiguration;
import cu.entalla.security.pkce.PKCEAuthorizationCodeTokenRequestEntityConverter;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.util.AccessTokenValidator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.cbor.MappingJackson2CborHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.converter.smile.MappingJackson2SmileHttpMessageConverter;
import org.springframework.http.converter.xml.MappingJackson2XmlHttpMessageConverter;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.logging.Logger;

@Service
@Data
public class AuthenticationService {

    private Wso2AuthenticatorClient client;
    private OidcIdToken oidcIdToken;
    private static final Logger logger = Logger.getLogger(AuthenticationService.class.getName());

    public AuthenticationService(Wso2AuthenticatorClient client) {
        this.client=client;
    }
    public AuthenticationService(Wso2AuthenticatorClient client,OidcIdToken oidcIdToken) {
        this.client=client;
        this.oidcIdToken=oidcIdToken;
    }
    public AuthenticationService() {

    }
    public OpenIDConfiguration discoverOidcEndPoints(String propertyFilePath) throws Exception {
        if(!new File(propertyFilePath).exists())
            throw new EnTallaFileNotExistException("La url especificada para iniciar las configuraciones no existe:"+propertyFilePath);
        String data = Wso2AuthenticatorClient.discoverOidcEndPoints(propertyFilePath);
        if(data==null)
            throw new EmptyOidcEndPointException("Error al intentar devolver los endpoint oidc con la configuración iniciada desde:"+propertyFilePath);
        return OpenIDConfiguration.loadFromJson(data);
    }
    public boolean hasOpenIdConfigurationLoaded(){
        return AuthenticationStore.getInstance().getOpenIdConfiguration()!=null;
    }
    public AuthenticationService authenticationWithCodeFlow() throws EmptyOpenIdConfigurationException, EmptyWso2AuthenticatorClient {
        //1-Get the authorization code
        String authorizationCode=getAuthorizationCode();
        return this;
    }
    public AuthenticationService authenticationWithCodeFlow(String Id) throws EmptyOpenIdConfigurationException, EmptyWso2AuthenticatorClient {
        //1-Get the authorization code
        String authorizationCode=getAuthorizationCode(Id);
        return this;
    }
    public String getAutorizationUri(String Id) throws IOException {
        AuthorizationRequestModel requestModel=new AuthorizationRequestModel();
        return requestModel.buildAuthorizeUrl(Id);
    }
    public AuthenticationService authenticationWithCodeFlowAndPkce(){
        return this;
    }
    public AuthenticationService authenticationWithPrivateKeyJwt(){
        return this;
    }
    public AuthenticationService authenticationWithPushedAuthorizationRequest(){
        return this;
    }
    public AuthenticationService authenticationWithDeviceAuthorizationFlow(){
        return this;
    }
    public AuthenticationService authenticationWithHybridFlow(){
        return this;
    }
    public AuthenticationService configureTokenExchange(){
        return this;
    }
    public AuthenticationService validateIdTokens(){
        return this;
    }
    public AuthenticationService validateTokens(){
        return this;
    }
    public AuthenticationService requestUserInformation(){
        return this;
    }
    public AuthenticationService revokeToken(){
        return this;
    }
    public AuthenticationService logout(){
        return this;
    }
    public AuthenticationService backChannelLogout(){
        return this;
    }
    public AuthenticationService federatedIdpInitiatedLogout(){
        return this;
    }

    public AuthenticationService initWso2AuthenticatorClient(){
        if(client==null){
            // Obtener el valor de CATALINA_BASE
            String catalinaBase = System.getenv("CATALINA_BASE");
            if(catalinaBase==null)
                catalinaBase="/media/datos/Instaladores/entalla/tomcat";
            if(catalinaBase!=null)                
            client = Wso2AuthenticatorClient.create(catalinaBase+"/shared/classes/alfresco-global.properties");
        }
        return this;
    }
    public Wso2AuthenticatorClient getClient(){
        initWso2AuthenticatorClient();
        return client;
    }
    public String getAuthorizationCode() throws EmptyOpenIdConfigurationException, EmptyWso2AuthenticatorClient {
        OpenIDConfiguration conf= AuthenticationStore.getInstance().getOpenIdConfiguration();
        String authorizationCode=null;
        if(conf==null)
            throw new EmptyOpenIdConfigurationException();
        initWso2AuthenticatorClient();
        if(getClient()==null)
            throw new EmptyWso2AuthenticatorClient();
        authorizationCode= getClient().getAuthorizationCode();
        return authorizationCode;
    }
    public String getAuthorizationCode(String Id) throws EmptyOpenIdConfigurationException, EmptyWso2AuthenticatorClient {
        OpenIDConfiguration conf= AuthenticationStore.getInstance().getOpenIdConfiguration();
        String authorizationCode=null;
        if(conf==null)
            throw new EmptyOpenIdConfigurationException();
        initWso2AuthenticatorClient();
        if(getClient()==null)
            throw new EmptyWso2AuthenticatorClient();
        authorizationCode= getClient().getAuthorizationCode(Id);
        return authorizationCode;
    }

    public Map<String, Object> createOidcClaims(JWTClaimsSet claims) throws ParseException {
        // Crear un mapa con los claims para el OidcIdToken
        Map<String, Object> oidcClaims = new HashMap<>();

        // Agregar todos los claims presentes en el JWT
        claims.getClaims().forEach(oidcClaims::put);

        // Opcional: asegurarte de agregar algunos claims estándar con nombres correctos
        oidcClaims.putIfAbsent(StandardClaimNames.SUB, claims.getSubject());
        oidcClaims.putIfAbsent(StandardClaimNames.EMAIL, claims.getStringClaim("email"));
        oidcClaims.putIfAbsent(StandardClaimNames.PHONE_NUMBER, claims.getStringClaim("phone_number"));
        oidcClaims.putIfAbsent(StandardClaimNames.PREFERRED_USERNAME, claims.getStringClaim("preferred_username"));
        oidcClaims.putIfAbsent("username", claims.getStringClaim("username"));

        return oidcClaims;
    }
    public String decodeToken(String idToken) {
        String payLoad=null;
        try
        {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(idToken);
            payLoad=signedJWT.getPayload().toString();
            // Obtener los claims del JWT
            var claims = signedJWT.getJWTClaimsSet();

            // Extraer las fechas de emisión y expiración
            var issuedAt = claims.getIssueTime().toInstant();
            var expiresAt = claims.getExpirationTime().toInstant();

            // Crear un mapa con los claims para el OidcIdToken
            Map<String, Object> oidcClaims = createOidcClaims(claims);
            oidcClaims.put(StandardClaimNames.SUB, claims.getSubject());
            oidcClaims.put(StandardClaimNames.EMAIL, claims.getStringClaim("email"));
            oidcClaims.put(StandardClaimNames.NAME, claims.getStringClaim("name"));
            oidcClaims.put(StandardClaimNames.SUB, claims.getStringClaim("sub"));
            oidcClaims.put("username", claims.getStringClaim("username"));
            oidcClaims.put(StandardClaimNames.PREFERRED_USERNAME, claims.getStringClaim("preferred_username"));
            oidcClaims.put(StandardClaimNames.PHONE_NUMBER, claims.getStringClaim("phone_number"));
            //oidcClaims.put(StandardClaimNames.ROLES, claims.getClaim("roles")); // Asegúrate de que el campo exista en el accessToken

            // Devolver una instancia de OidcIdToken
            oidcIdToken= new OidcIdToken(idToken, issuedAt, expiresAt, oidcClaims);
            logger.info("Decoded JWT Payload: " + payLoad);
            return payLoad;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private RestTemplate customRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());
        restTemplate.getMessageConverters().add(new MappingJackson2CborHttpMessageConverter());
        restTemplate.getMessageConverters().add(new MappingJackson2SmileHttpMessageConverter());
        restTemplate.getMessageConverters().add(new MappingJackson2XmlHttpMessageConverter());
        return restTemplate;
    }
    public boolean isAuthenticated(String userName,String accessToken) {
        // Verificar si el usuario ya está autenticado
        return userName != null && AccessTokenValidator.isValidAccessToken(accessToken);
    }
    public boolean isAuthenticated(String userName) {
        // Verificar si el usuario ya está autenticado
        return userName != null;
    }
    public boolean isAuthenticated(HttpServletRequest request) {
        // Verificar si el usuario ya está autenticado
        Wso2SecurityConfig alfConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        String user = (String) request.getSession().getAttribute(alfConfig.getAuthenticatedUserKeyWord());
        return user != null;
    }
    public boolean isAuthenticated(HttpSession session) {
        // Verificar si el usuario ya está autenticado
        Wso2SecurityConfig alfConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        String user = (String) session.getAttribute(alfConfig.getAuthenticatedUserKeyWord());
        return user != null;
    }
    public boolean isAuthenticated(Cookie cookie) {
        // Verificar si el usuario ya está autenticado
        if(cookie==null) return false;
        Wso2SecurityConfig alfConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        String user = (String) (cookie.getName().equals(alfConfig.getAuthenticatedUserKeyWord())?cookie.getValue():null);
        return user != null;
    }

    public String getCustomAccessToken(String code, String codeVerifier) throws Exception {
        logger.info("getAccessToken using PKCE...");
        if(!AuthenticationStore.getInstance().hasClientRegistrationRepository()){
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }
        return getClient().getAccessToken(code,codeVerifier);
    }
    public String getCustomAccessToken(HttpServletRequest request, String code, String codeVerifier) throws Exception {
        logger.info("getAccessToken using PKCE...");
        if(!AuthenticationStore.getInstance().hasClientRegistrationRepository()){
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }
        return getClient().getAccessToken(request,code,codeVerifier);
    }
    public String getCustomAccessToken(HttpServletRequest request, String code) throws Exception {
        logger.info("getAccessToken using PKCE...");
        if(!AuthenticationStore.getInstance().hasClientRegistrationRepository()){
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }
        return getClient().getAccessToken(request,code);
    }
    public String getCustomAccessToken(String code) throws Exception {
        logger.info("getAccessToken not using PKCE...");
        if(!AuthenticationStore.getInstance().hasClientRegistrationRepository()){
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }
        return getClient().getAccessToken(getClient().getServletRequest(), code);
    }

    public OidcIdToken createOidcToken(ClientRegistration clientRegistration, String accessToken) throws ParseException, JOSEException, MalformedURLException {
        // Parsear el accessToken como un SignedJWT
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        Wso2SecurityConfig alfConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        // Obtener la clave pública desde el JWKS endpoint
        RemoteJWKSet<?> jwkSet = new RemoteJWKSet<>(new URL(alfConfig.getJwkSetUri()));

        // Crear un JWKMatcher para encontrar la clave por KeyID
        String keyID = signedJWT.getHeader().getKeyID();
        JWKMatcher matcher = new JWKMatcher.Builder().keyID(keyID).build();
        JWKSelector selector = new JWKSelector(matcher);

        JWK matchingJWK = jwkSet.get(selector, null).get(0);

        RSAKey rsaKey = (RSAKey) matchingJWK;
        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

        // Verificar la firma del JWT
        RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
        if (!signedJWT.verify(verifier)) {
            throw new SecurityException("La firma del accessToken no es válida.");
        }

        // Obtener los claims del JWT
        var claims = signedJWT.getJWTClaimsSet();

        // Extraer las fechas de emisión y expiración
        var issuedAt = claims.getIssueTime().toInstant();
        var expiresAt = claims.getExpirationTime().toInstant();

        // Crear un mapa con los claims para el OidcIdToken
        Map<String, Object> oidcClaims = new HashMap<>();
        oidcClaims.put(StandardClaimNames.SUB, claims.getSubject());
        oidcClaims.put(StandardClaimNames.EMAIL, claims.getStringClaim("email"));
        oidcClaims.put(StandardClaimNames.NAME, claims.getStringClaim("name"));
        oidcClaims.put(StandardClaimNames.SUB, claims.getStringClaim("sub"));
        oidcClaims.put("username", claims.getStringClaim("username"));
        oidcClaims.put(StandardClaimNames.PREFERRED_USERNAME, claims.getStringClaim("preferred_username"));
        oidcClaims.put(StandardClaimNames.PHONE_NUMBER, claims.getStringClaim("phone_number"));
        //oidcClaims.put(StandardClaimNames.ROLES, claims.getClaim("roles")); // Asegúrate de que el campo exista en el accessToken

        // Devolver una instancia de OidcIdToken
        return this.oidcIdToken= new OidcIdToken(accessToken, issuedAt, expiresAt, oidcClaims);
    }
    public OAuth2AccessTokenResponse getAccessToken(String code, String codeVerifier) throws Exception {
        logger.info("getAccessToken using PKCE...");
        if(!AuthenticationStore.getInstance().hasClientRegistrationRepository()){
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }
        ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
        logger.info("clientRegistration:"+clientRegistration.toString());
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .clientId(clientRegistration.getClientId())
                .redirectUri(clientRegistration.getRedirectUri())
                .build();
        logger.info("authorizationRequest:"+authorizationRequest.toString());
        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success(code)
                .redirectUri(clientRegistration.getRedirectUri())
                .build();
        logger.info("authorizationResponse:"+authorizationResponse.toString());
        OAuth2AuthorizationExchange exchange = new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
        logger.info("exchange:"+exchange.toString());
        OAuth2AuthorizationCodeGrantRequest tokenRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration, exchange);
        logger.info("tokenRequest:"+tokenRequest.toString());
        // Incluir el code_verifier en la solicitud de token
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        logger.info("tokenResponseClient:"+tokenResponseClient.toString());
       tokenResponseClient.setRequestEntityConverter(request -> {
            RequestEntity entity = new PKCEAuthorizationCodeTokenRequestEntityConverter().convert(request);
            LinkedHashMap body = new LinkedHashMap<>((MultiValueMap)entity.getBody());
            body.put("code_verifier", codeVerifier);
            return new RequestEntity<>(body, entity.getHeaders(), entity.getMethod(), entity.getUrl());
        });
        //tokenResponseClient.setRestOperations(customRestTemplate());
        OAuth2AccessTokenResponse result= tokenResponseClient.getTokenResponse(tokenRequest);
        logger.info("OAuth2AccessTokenResponse:"+result.toString());
        return result;
    }

    public boolean isValidToken(String accessToken){
        return AccessTokenValidator.isValidAccessToken(accessToken);
    }
    public OAuth2AccessTokenResponse getAccessToken(String code) throws Exception {
        logger.info("getAccessToken...");

        if (!AuthenticationStore.getInstance().hasClientRegistrationRepository()) {
            throw new Exception("No existe una instancia válida de ClientRegistrationRepository.");
        }

        ClientRegistration clientRegistration = AuthenticationStore.getInstance().getClientRegistrationRepository().findByRegistrationId("wso2");
        logger.info("clientRegistration: " + clientRegistration);

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .clientId(clientRegistration.getClientId())
                .redirectUri(clientRegistration.getRedirectUri())
                .build();

        OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success(code)
                .redirectUri(clientRegistration.getRedirectUri())
                .build();

        OAuth2AuthorizationExchange exchange = new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);

        OAuth2AuthorizationCodeGrantRequest tokenRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration, exchange);

        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRestOperations(customRestTemplate());

        try {
            OAuth2AccessTokenResponse accessTokenResponse = tokenResponseClient.getTokenResponse(tokenRequest);
            if (accessTokenResponse.getAccessToken() == null) {
                logger.severe("El servidor OAuth2 no devolvió un access_token. Respuesta: " + accessTokenResponse);
                throw new RuntimeException("El servidor no devolvió un access_token.");
            }
            logger.info("accessTokenResponse: " + accessTokenResponse);
            return accessTokenResponse;
        } catch (Exception e) {
            logger.severe("Error al obtener el token: " + e.getMessage());
            throw new RuntimeException("Error en la solicitud de token de acceso.", e);
        }
    }


    public String getRequestUriWithOutPAR(String codeChallenge){
        Wso2SecurityConfig alfConfig=AuthenticationStore.getInstance().getWso2SecurityConfig();
        String authorizationUri = alfConfig.getAuthorizationUri()
                + "?response_type=code"
                + "&client_id=" + URLEncoder.encode(alfConfig.getClientId(), StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(alfConfig.getRedirectUri(), StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(alfConfig.getScope(), StandardCharsets.UTF_8)
                + "&code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)
                + "&code_challenge_method=S256";
        logger.info("REQUEST_URI SIN PAR: " + authorizationUri);
        return authorizationUri;
    }
    public String getRequestUriUsingPAR(ClientRegistration clientRegistration, String codeChallenge)
            throws IOException, InterruptedException, NoSuchAlgorithmException, KeyManagementException {

        logger.info("Ejecutando: getRequestUriUsingPAR");

        // Endpoint de PAR
        String parEndpoint = AuthenticationStore.getInstance().getWso2SecurityConfig().getParUri();
        logger.info("PAR ENDPOINT: " + parEndpoint);

        // Generar Code Verifier
        String codeVerifier = AuthenticationStore.getInstance().getWso2SecurityConfig().generateCodeVerifier();
        logger.info("codeVerifier: " + codeVerifier);

        // Construir parámetros del cuerpo de la solicitud
        StringJoiner params = new StringJoiner("&");
        params.add("client_id=" + URLEncoder.encode(clientRegistration.getClientId(), StandardCharsets.UTF_8));
        params.add("response_type=code");
        params.add("redirect_uri=" + URLEncoder.encode(clientRegistration.getRedirectUri(), StandardCharsets.UTF_8));
        params.add("code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8));
        params.add("code_challenge_method=S256");
        params.add("scope=" + URLEncoder.encode(String.join(" ", clientRegistration.getScopes()), StandardCharsets.UTF_8));
        logger.info("PARAMS: " + params.toString());

        // Configurar SSLContext que confía en todos los certificados
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{AuthenticationStore.getInstance().getTrustManager()}, new java.security.SecureRandom());

        // Configurar HostnameVerifier que confía en todos los hosts
        HostnameVerifier allHostsValid = (hostname, session) -> true;

        // Crear HttpClient con el SSLContext y HostnameVerifier personalizados
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(new SSLParameters()) // Opcional, mejora compatibilidad
                .build();

        // Construir la solicitud HTTP POST
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(parEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .build();

        // Enviar la solicitud y capturar la respuesta
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

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
                throw new IOException("La respuesta PAR no contiene el campo 'request_uri'.");
            }
        } else {
            throw new IOException("Error al obtener la URI de solicitud PAR: " + response.statusCode() + " " + response.body());
        }
    }

    public String getUserInfoAsString(Map<String, Object> userInfo){
        // Convertir Map a JSON
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(userInfo);
            System.out.println("UserInfo en JSON: " + json);
            logger.info("UserInfo en JSON:"+json);
            return json;
        } catch (Exception e) {
            e.printStackTrace();
            logger.severe("Error al convertir userInfo a JSON"+ e.getMessage());
        }
        return null;
    }
    public Map<String, Object> getUserInfo(String accessToken) throws IOException, InterruptedException {
        logger.info("getUserInfo with accessToken:"+accessToken);
        // Construir la URI para el endpoint de información del usuario
        String userInfoUri = AuthenticationStore.getInstance().getWso2SecurityConfig().getUserInfoUri();
        if(userInfoUri==null) {
            AuthenticationStore.getInstance().getWso2SecurityConfig().loadProperties();
            userInfoUri = AuthenticationStore.getInstance().getWso2SecurityConfig().getUserInfoUri();
            logger.info("La URI es igual a:"+userInfoUri+" y no sé por qué...");
            userInfoUri=userInfoUri!=null?userInfoUri:"https://ses-idp.entalla.cu:9444/oauth2/userinfo";
        }
        else
            logger.info("La URI es igual a:"+userInfoUri+" y se está leyendo bien...");
        logger.info("userInfoUri:"+userInfoUri);
        URI uri = URI.create(userInfoUri + "?access_token=" + accessToken);
        // Crear el cliente HTTP
        HttpClient client = Wso2AuthenticatorClient.getInstance().getHttpClient();
        // Construir la solicitud HTTP
        logger.info("sending request to get userInfo:"+uri.toString());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", "Bearer " + accessToken) // Header opcional si tu servidor requiere este formato
                .GET()
                .build();
        // Enviar la solicitud y obtener la respuesta
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        logger.info("statusCode:"+response.statusCode());
        if (response.statusCode() == 200) {
            // Convertir la respuesta JSON en un Map
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(response.body(), Map.class);
        } else {
            throw new RuntimeException("Error al obtener información del usuario: " + response.body());
        }
    }

    /*public void setShareSession(OAuth2AuthenticationToken authentication) throws IOException {
        UserService userService = new UserService();
        //userService.setShareSession(authentication);
    }
    public void setShareSession(UserService userService,OAuth2AuthenticationToken authentication) throws IOException {
       //userService.setShareSession(authentication);
    }*/

}
