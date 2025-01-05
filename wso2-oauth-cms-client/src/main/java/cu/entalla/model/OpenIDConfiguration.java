package cu.entalla.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import cu.entalla.store.AuthenticationStore;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.List;

@Data
@NoArgsConstructor
public class OpenIDConfiguration {

    @JsonProperty("request_parameter_supported")
    private boolean requestParameterSupported;  // Mapea el JSON "request_parameter_supported" al atributo requestParameterSupported

    @JsonProperty("pushed_authorization_request_endpoint")
    private String pushedAuthorizationRequestEndpoint;

    @JsonProperty("claims_parameter_supported")
    private boolean claimsParameterSupported;

    @JsonProperty("introspection_endpoint")
    private String introspectionEndpoint;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;

    @JsonProperty("check_session_iframe")
    private String checkSessionIframe;

    @JsonProperty("backchannel_logout_supported")
    private boolean backchannelLogoutSupported;

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("introspection_endpoint_auth_methods_supported")
    private List<String> introspectionEndpointAuthMethodsSupported;

    @JsonProperty("device_authorization_endpoint")
    private String deviceAuthorizationEndpoint;

    @JsonProperty("claims_supported")
    private List<String> claimsSupported;

    @JsonProperty("userinfo_signing_alg_values_supported")
    private List<String> userinfoSigningAlgValuesSupported;

    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;

    @JsonProperty("tls_client_certificate_bound_access_tokens")
    private boolean tlsClientCertificateBoundAccessTokens;

    @JsonProperty("response_modes_supported")
    private List<String> responseModesSupported;

    @JsonProperty("backchannel_logout_session_supported")
    private boolean backchannelLogoutSessionSupported;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;

    @JsonProperty("revocation_endpoint_auth_methods_supported")
    private List<String> revocationEndpointAuthMethodsSupported;

    @JsonProperty("webfinger_endpoint")
    private String webfingerEndpoint;

    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported;

    @JsonProperty("end_session_endpoint")
    private String endSessionEndpoint;

    @JsonProperty("revocation_endpoint")
    private String revocationEndpoint;

    @JsonProperty("userinfo_endpoint")
    private String userinfoEndpoint;

    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;

    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported;

    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported;

    @JsonProperty("registration_endpoint")
    private String registrationEndpoint;

    @JsonProperty("request_object_signing_alg_values_supported")
    private List<String> requestObjectSigningAlgValuesSupported;

    /**
     * Método para convertir la instancia de OpenIDConfiguration a un JSON.
     *
     * @return El JSON como String.
     * @throws JsonProcessingException Si ocurre un error durante la serialización.
     */
    public String toJson() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(this);
    }
    /**
     * Método para inicializar la clase desde un JSON.
     *
     * @param json El JSON en formato String.
     * @return Una instancia de OpenIDConfiguration con las propiedades cargadas.
     * @throws Exception Si ocurre un error durante el parseo del JSON.
     */
    public static OpenIDConfiguration loadFromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        OpenIDConfiguration openId=mapper.readValue(json, OpenIDConfiguration.class);
        AuthenticationStore.getInstance().setOpenIdConfiguration(openId);
        return openId;
    }
}
