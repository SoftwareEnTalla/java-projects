package cu.entalla.model;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.udi.EventHandler;
import lombok.Data;
import cu.entalla.nomenclature.AuthMethod;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Data
public class TokenRequestModel implements EventHandler {

    private String code;
    private String grantType;
    private String redirectUri;
    private String clientId;
    private String clientSecret;  // No se usará en PKCE
    private String accessToken;
    private String idToken;
    private String refreshToken;

    // Atributos relacionados con la autenticación del cliente utilizando JWT privado (si es necesario)
    private String clientAssertionType;
    private String clientAssertion;

    // Atributos relacionados con PKCE (Proof Key for Code Exchange)
    private String codeVerifier;  // Nuevo atributo para el code_verifier en PKCE

    // Mapa de headers a enviar
    private Map<String, Object> _headers = new HashMap<>();

    private boolean pkceFlow;  // Atributo para indicar si se utiliza PKCE
    private boolean parFlow;
    private String tokenUrl;
    private boolean initialized=false;

    /**
     * Inicializa los atributos a partir de un archivo de propiedades.
     *
     * @param filePath Ruta al archivo de propiedades.
     * @throws java.io.IOException Si ocurre un error al leer el archivo.
     */
    private void loadFromProperties(String filePath) throws IOException {
        loadFromProperties(filePath,"wso2");
    }
    /**
     * Inicializa los atributos a partir de un archivo de propiedades.
     *
     * @param filePath Ruta al archivo de propiedades.
     * @throws java.io.IOException Si ocurre un error al leer el archivo.
     */
    private void loadFromProperties(String filePath,String Id) throws IOException {
        Properties properties = new Properties();

        // Cargar propiedades desde el archivo
        try (FileInputStream fis = new FileInputStream(filePath)) {
            properties.load(fis);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Mapear propiedades a los atributos
        this.redirectUri = properties.getProperty("oauth2.client.registration."+Id+".redirect-uri");
        this.clientId = properties.getProperty("oauth2.client.registration."+Id+".client-id");
        this.tokenUrl = properties.getProperty("oauth2.client.provider."+Id+".token-uri");
        this.pkceFlow = Boolean.parseBoolean(properties.getProperty("oauth2.client.registration."+Id+".pkce-flow", "false"));
        this.parFlow = Boolean.parseBoolean(properties.getProperty("oauth2.client.provider."+Id+".par-enabled", "false"));
        this.grantType=properties.getProperty("oauth2.client.registration."+Id+".authorization-grant-type");
        this.initialized = true;
    }
    public void loadFromConfig(Wso2SecurityConfig config) throws IOException {

        if(!config.isLoaded())
            config.loadProperties();
        // Mapear propiedades a los atributos
        this.redirectUri = config.getRedirectUri();
        this.clientId = config.getClientId();
        this.tokenUrl = config.getTokenUri();
        this.pkceFlow =  config.isPkceFlow();
        this.parFlow =  config.getParEnable();
        this.grantType=config.getAuthorizationGrantType();
        this.initialized = true;
    }
    public TokenRequestModel inicialize(String id) throws IOException {
        Wso2SecurityConfig conf= AuthenticationStore.getInstance().getWso2SecurityConfig();
        if(conf!=null){
            loadFromConfig(conf);
            return this;
        }
        String catalinaBase = System.getenv("CATALINA_BASE");
        if(catalinaBase==null)
            catalinaBase="/media/datos/Instaladores/entalla/tomcat";
        if(!initialized && catalinaBase!=null){
            loadFromProperties(catalinaBase+"/shared/classes/alfresco-global.properties",id);
            initialized=true;
        }
        return this;
    }

    /**
     * Construye la URL para hacer la solicitud de token.
     * Depende del método de autenticación seleccionado.
     *
     * @param authMethod El método de autenticación utilizado.
     * @return La URL de solicitud de token.
     */
    public String buildTokenRequestUrl(String authMethod) {


        StringBuilder urlBuilder = new StringBuilder(tokenUrl);

        // Parámetros comunes
        urlBuilder.append("?code=").append(code)
                .append("&grant_type=").append(grantType)
                .append("&redirect_uri=").append(redirectUri);

        // Inicializar el _headers HashMap según el tipo de autenticación
        _headers.clear();  // Limpiar _headers antes de agregar nuevos

        switch (AuthMethod.fromString(authMethod.toLowerCase())) {
            case CLIENT_SECRET_POST:
                // Si el método es client_secret_post, los parámetros se envían en el cuerpo
                urlBuilder.append("&client_id=").append(clientId)
                        .append("&client_secret=").append(clientSecret); // Aquí se usa client_secret
                break;
            case CLIENT_SECRET_BASIC:
                // Si el método es client_secret_basic, los parámetros van en la cabecera Authorization
                // Construir la cabecera Authorization en base64
                String authHeader = clientId + ":" + clientSecret;
                String encodedAuthHeader = Base64.getEncoder().encodeToString(authHeader.getBytes());

                // Construir la cabecera Authorization
                _headers.put("Authorization", "Basic " + encodedAuthHeader);

                // No se agregan client_id y client_secret a la URL en este caso, ya están en los headers
                break;
            case CLIENT_SECRET_JWT:
                // Si el método es client_secret_jwt, utilizamos client_assertion
                urlBuilder.append("&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        .append("&client_assertion=").append(clientAssertion);
                break;
            case PRIVATE_KEY_JWT:
                // Si el método es private_key_jwt, la autenticación es mediante JWT firmado
                urlBuilder.append("&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        .append("&client_assertion=").append(clientAssertion);
                break;
            case TLS_CLIENT_AUTH:
                // Si el flujo es PKCE, añadir el code_verifier a la URL (sin client_secret)
                if (codeVerifier != null && !codeVerifier.isEmpty()) {
                    urlBuilder.append("&code_verifier=").append(codeVerifier);
                } else {
                    throw new IllegalArgumentException("El code_verifier es obligatorio para el flujo PKCE");
                }
                break;
            case PKCE:
                // Si el flujo es PKCE, añadir el code_verifier a la URL (sin client_secret)
                if (codeVerifier != null && !codeVerifier.isEmpty()) {
                    urlBuilder.append("&code_verifier=").append(codeVerifier);
                } else {
                    throw new IllegalArgumentException("El code_verifier es obligatorio para el flujo PKCE");
                }
                break;
            default:
                throw new IllegalArgumentException("Método de autenticación no soportado: " + authMethod);
        }

        return urlBuilder.toString();
    }


    /**
     * Devuelve los encabezados generados para la solicitud.
     *
     * @return Los encabezados de la solicitud.
     */
    public Map<String, Object> getHeaders() {
        return _headers;
    }
}


