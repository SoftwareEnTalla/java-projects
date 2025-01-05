package cu.entalla.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserProfile {

    @JsonProperty("sub")
    private String subject;

    @JsonProperty("aut")
    private String authority;

    @JsonProperty("binding_type")
    private String bindingType;

    @JsonProperty("iss")
    private String issuer;

    @JsonProperty("given_name")
    private String givenName;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("aud")
    private String audience;

    @JsonProperty("nbf")
    private long notBefore;

    @JsonProperty("azp")
    private String authorizedParty;

    @JsonProperty("org_id")
    private String organizationId;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("phone_number")
    private String phoneNumber;

    @JsonProperty("exp")
    private long expirationTime;

    @JsonProperty("org_name")
    private String organizationName;

    @JsonProperty("iat")
    private long issuedAt;

    @JsonProperty("family_name")
    private String familyName;

    @JsonProperty("binding_ref")
    private String bindingReference;

    @JsonProperty("jti")
    private String jwtId;

    @JsonProperty("email")
    private String email;

    @JsonProperty("username")
    private String username;

    public static UserProfile fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, UserProfile.class);
    }
    // Convierte el objeto UserProfile a JSON
    public String toJson() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }
    public long getExpirationTimestamp() {
        return expirationTime * 1000L; // Convierte segundos en milisegundos
    }
}
