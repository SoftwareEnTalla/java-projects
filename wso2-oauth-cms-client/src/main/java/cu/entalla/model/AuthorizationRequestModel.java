package cu.entalla.model;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.store.AuthenticationStore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthorizationRequestModel {

    private boolean initialized=false;
    private String privateKey;
    // Atributos correspondientes a los parámetros
    private String scope;
    private String responseType;
    private String redirectUri;
    private String clientId;
    private String loginHint;
    private String authorizeUrl;
    private boolean pkceFlow;  // Atributo para indicar si se utiliza PKCE
    private boolean parFlow;
    private String codeChallenge;  // Valor para el code_challenge (debe ser calculado en otro lugar)
    private String codeChallengeMethod;  // Método para el code_challenge (por ejemplo, "S256")
    private String requestUri;

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
        this.scope = properties.getProperty("oauth2.client.registration."+Id+".scope");
        this.responseType =properties.getProperty("oauth2.client.registration."+Id+".responseType","code"); // Generalmente fijo para OAuth2
        this.redirectUri = properties.getProperty("oauth2.client.registration."+Id+".redirect-uri");
        this.clientId = properties.getProperty("oauth2.client.registration."+Id+".client-id");
        this.loginHint = properties.getProperty("oauth2.client.registration."+Id+".login-hint", ""); // Opcional
        this.authorizeUrl = properties.getProperty("oauth2.client.provider."+Id+".authorization-uri");
        this.pkceFlow = Boolean.parseBoolean(properties.getProperty("oauth2.client.registration."+Id+".pkce-flow", "false"));
        this.parFlow = Boolean.parseBoolean(properties.getProperty("oauth2.client.provider."+Id+".par-enabled", "false"));
        this.privateKey = properties.getProperty("oauth2.client.registration."+Id+".private-key");
        this.initialized = true;
    }
    public void loadFromConfig(Wso2SecurityConfig config) throws IOException {

        if(!config.isLoaded())
            config.loadProperties();
        // Mapear propiedades a los atributos
        this.scope = config.getScope();
        this.responseType = config.getResponseType(); // Generalmente fijo para OAuth2
        this.redirectUri = config.getRedirectUri();
        this.clientId = config.getClientId();
        this.loginHint = config.getLoginHint();
        this.authorizeUrl = config.getAuthorizationUri();
        this.pkceFlow =  config.isPkceFlow();
        this.parFlow = config.getParEnable();
        this.privateKey = config.getPrivateKeyPath();
        this.initialized = true;
    }
    public AuthorizationRequestModel inicialize(String id) throws IOException {
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
    public String buildAuthorizeUrl(String Id) throws IOException {
        if (!initialized) {
            inicialize(Id);
        }

        StringBuilder urlBuilder = new StringBuilder();
        // Parámetro opcional: login_hint
        String loginHintPart = loginHint != null && !loginHint.isEmpty()
                ? "&login_hint=" + URLEncoder.encode(loginHint, StandardCharsets.UTF_8)
                : "";

        if (pkceFlow && parFlow) {
            // PKCE + PAR habilitados
            urlBuilder.append(authorizeUrl)
                    .append("?request_uri=")
                    .append(URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
        } else if (pkceFlow) {
            // Solo PKCE habilitado
            urlBuilder.append(authorizeUrl)
                    .append("?scope=")
                    .append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&response_type=")
                    .append(URLEncoder.encode(responseType, StandardCharsets.UTF_8))
                    .append("&redirect_uri=")
                    .append(URLEncoder.encode(requestUri, StandardCharsets.UTF_8))
                    .append("&client_id=")
                    .append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append(loginHintPart)
                    .append("&code_challenge=")
                    .append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8))
                    .append("&code_challenge_method=")
                    .append(URLEncoder.encode(codeChallengeMethod, StandardCharsets.UTF_8));
        } else {
            // Sin PKCE
            urlBuilder.append(authorizeUrl)
                    .append("?scope=")
                    .append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&response_type=")
                    .append(URLEncoder.encode(responseType, StandardCharsets.UTF_8))
                    .append("&redirect_uri=")
                    .append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8))
                    .append("&client_id=")
                    .append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append(loginHintPart);
        }

        return urlBuilder.toString();
    }
    // Método para construir la URL de autorización completa
    public String buildAuthorizeUrl() throws IOException {
        if (!initialized) {
            inicialize("wso2");
        }

        StringBuilder urlBuilder = new StringBuilder();
        // Parámetro opcional: login_hint
        String loginHintPart = loginHint != null && !loginHint.isEmpty()
                ? "&login_hint=" + URLEncoder.encode(loginHint, StandardCharsets.UTF_8)
                : "";

        if (pkceFlow && parFlow) {
            // PKCE + PAR habilitados
            urlBuilder.append(authorizeUrl)
                    .append("?request_uri=")
                    .append(URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
        } else if (pkceFlow) {
            // Solo PKCE habilitado
            urlBuilder.append(authorizeUrl)
                    .append("?scope=")
                    .append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&response_type=")
                    .append(URLEncoder.encode(responseType, StandardCharsets.UTF_8))
                    .append("&redirect_uri=")
                    .append(URLEncoder.encode(requestUri, StandardCharsets.UTF_8))
                    .append("&client_id=")
                    .append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append(loginHintPart)
                    .append("&code_challenge=")
                    .append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8))
                    .append("&code_challenge_method=")
                    .append(URLEncoder.encode(codeChallengeMethod, StandardCharsets.UTF_8));
        } else {
            // Sin PKCE
            urlBuilder.append(authorizeUrl)
                    .append("?scope=")
                    .append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&response_type=")
                    .append(URLEncoder.encode(responseType, StandardCharsets.UTF_8))
                    .append("&redirect_uri=")
                    .append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8))
                    .append("&client_id=")
                    .append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append(loginHintPart);
        }

        return urlBuilder.toString();
    }


    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder("AuthorizationRequestModel{");

        // Construir los parámetros comunes
        stringBuilder.append("scope='").append(scope).append('\'')
                .append(", responseType='").append(responseType).append('\'')
                .append(", redirectUri='").append(redirectUri).append('\'')
                .append(", clientId='").append(clientId).append('\'');

        if (loginHint != null && !loginHint.isEmpty()) {
            stringBuilder.append(", loginHint='").append(URLEncoder.encode(loginHint, StandardCharsets.UTF_8)).append('\'');
        }


        // Verificar el flujo PKCE y PAR
        if (pkceFlow && parFlow) {
            stringBuilder.append(", pkceFlow=true")
                    .append(", parFlow=true")
                    .append(", requestUri='").append(requestUri).append('\'');
        } else if (pkceFlow) {
            stringBuilder.append(", pkceFlow=true")
                    .append(", codeChallenge='").append(codeChallenge).append('\'')
                    .append(", codeChallengeMethod='").append(codeChallengeMethod).append('\'');
        } else {
            stringBuilder.append(", pkceFlow=false");
        }

        // Agregar la URL del autorizador
        stringBuilder.append(", authorizeUrl='").append(authorizeUrl).append('\'');

        stringBuilder.append('}');

        return stringBuilder.toString();
    }

}
