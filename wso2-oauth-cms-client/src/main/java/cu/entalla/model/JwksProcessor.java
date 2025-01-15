package cu.entalla.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Represents the structure of a JSON Web Key Set (JWKS).
 */
public class JwksProcessor {

    @JsonProperty("keys")
    private List<JwkKey> keys;

    public List<JwkKey> getKeys() {
        return keys;
    }

    public void setKeys(List<JwkKey> keys) {
        this.keys = keys;
    }

    @Override
    public String toString() {
        return "JwksProcessor{" +
                "keys=" + keys +
                '}';
    }
}
