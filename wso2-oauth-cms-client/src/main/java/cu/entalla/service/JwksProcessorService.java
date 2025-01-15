package cu.entalla.service;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.model.JwkKey;
import lombok.Data;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true) // Ignora propiedades desconocidas en el JSON
public class JwksProcessorService {
    private List<JwkKey> keys;

    /**
     * Procesa la URL del recurso JWKS y mapea su contenido en esta clase.
     *
     * @param url La URL del JWKS.
     * @return Una instancia de JwksProcessorService con los valores mapeados.
     * @throws IOException Si ocurre un error al conectarse a la URL o procesar el JSON.
     * @throws InterruptedException Si la solicitud HTTP es interrumpida.
     */
    public static JwksProcessorService fromUrl(String url) throws IOException, InterruptedException {
        Wso2AuthenticatorClient client=Wso2AuthenticatorClient.getInstance();

        // Crear la solicitud GET
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .header("Accept", "application/json")
                .build();

        // Enviar la solicitud y obtener la respuesta
        HttpResponse<String> response = client.getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        // Verificar el código de estado HTTP
        if (response.statusCode() != 200) {
            throw new IOException("Error al conectar con la URL: " + url + ", código HTTP: " + response.statusCode());
        }

        // Convertir el cuerpo de la respuesta en un objeto JwksProcessorService
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.body(), JwksProcessorService.class);
    }

}
