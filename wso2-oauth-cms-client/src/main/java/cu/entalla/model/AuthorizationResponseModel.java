package cu.entalla.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthorizationResponseModel {
    // Atributos correspondientes a los parámetros de la URL
    @JsonProperty("code")
    private String code;
    @JsonProperty("session_state")
    private String sessionState;

    /**
     * Método para convertir la instancia de AuthorizationResponseModel a un JSON.
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
     * @return Una instancia de AuthorizationResponseModel con las propiedades cargadas.
     * @throws Exception Si ocurre un error durante el parseo del JSON.
     */
    public static AuthorizationResponseModel loadFromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, AuthorizationResponseModel.class);
    }
}
