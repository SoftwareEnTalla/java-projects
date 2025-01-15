package cu.entalla.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import cu.entalla.udi.EventHandler;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.Timer;
import java.util.Base64;
import java.util.Date;
import java.util.TimerTask;
import java.util.function.Function;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponseModel implements EventHandler, Serializable {

    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("scope")
    private String scope;
    @JsonProperty("id_token")
    private String idToken;
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("refresh_token")
    private String refreshToken;
    @JsonProperty("expires_in")
    private int expiresIn;

    private long expirationTimeInMillis;
    private Timer expirationTimer;

    public TokenResponseModel(String accessToken,String idToken,String tokenType,String scopes,int expiresIn){
        this.accessToken=accessToken;
        this.idToken=idToken;
        this.tokenType=tokenType;
        this.scope=scopes;
        this.expiresIn=expiresIn;
        initializeExpirationTimer();
    }
    public TokenResponseModel(String accessToken,String idToken,String tokenType,String scopes,String refreshToken,int expiresIn){
        this.accessToken=accessToken;
        this.idToken=idToken;
        this.tokenType=tokenType;
        this.scope=scopes;
        this.refreshToken=refreshToken;
        this.expiresIn=expiresIn;
        initializeExpirationTimer();
    }

    // Método que inicializa la fecha de expiración y programa un evento cuando el token expire
    public synchronized void initializeExpirationTimer() {
        expirationTimeInMillis = System.currentTimeMillis() + (expiresIn * 1000L);
        expirationTimer = new Timer();
        long delay = expirationTimeInMillis - System.currentTimeMillis();
        expirationTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                onTokenExpired();
            }
        }, delay);
    }

    // Método que se llama cuando el token ha expirado
    private synchronized void onTokenExpired() {
        System.out.println("El token ha expirado.");
        // Llamamos a notifyAll para notificar a todos los hilos esperando
        this.notifyAll();
        cancelExpirationTimer();
    }

    // Método para cancelar el temporizador si es necesario antes de la expiración
    public void cancelExpirationTimer() {
        if (expirationTimer != null) {
            expirationTimer.cancel();
        }
    }
    // Method to decode the Access Token
    public String decodeAccessToken() {
        String[] parts = accessToken.split("\\.");
        if (parts.length > 1) {
            return new String(Base64.getUrlDecoder().decode(parts[1]));
        }
        return null;
    }
    // Method to decode the Refresh Token
    public String decodeRefreshToken() {
        // Assuming similar JWT format as accessToken
        String[] parts = refreshToken.split("\\.");
        if (parts.length > 1) {
            return new String(Base64.getUrlDecoder().decode(parts[1]));
        }
        return null;
    }
    // Convert expiration to a Date timestamp
    public Date getExpirationTimestamp() {
        long currentTimeMillis = System.currentTimeMillis();
        long expirationMillis = currentTimeMillis + (expiresIn * 1000L);
        return new Date(expirationMillis);
    }
    @Override
    public String toString() {
        return "OAuth2Token{" +
                "accessToken='" + accessToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                ", scope='" + scope + '\'' +
                ", idToken='" + idToken + '\'' +
                ", tokenType='" + tokenType + '\'' +
                ", expiresIn=" + expiresIn +
                '}';
    }
    public static TokenResponseModel fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, TokenResponseModel.class);
    }
    public static TokenResponseModel fromJson(JSONObject json) {
        TokenResponseModel tokenResponse = new TokenResponseModel();

        // Extraer valores del JSONObject y asignarlos a los campos
        tokenResponse.setAccessToken(json.optString("access_token"));
        tokenResponse.setRefreshToken(json.optString("refresh_token"));
        tokenResponse.setScope(json.optString("scope"));
        tokenResponse.setIdToken(json.optString("id_token"));
        tokenResponse.setTokenType(json.optString("token_type"));
        tokenResponse.setExpiresIn(json.optInt("expires_in", 0)); // Valor predeterminado 0 si no está presente

        // Inicializar el temporizador de expiración si corresponde
        tokenResponse.initializeExpirationTimer();

        return tokenResponse;
    }
    // Convierte el objeto UserProfile a JSON
    public String toJson() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    /**
     * Método genérico para procesar datos de TokenResponseModel.
     *
     * @param processor La función que procesa la instancia.
     * @param returnType El tipo de clase que se espera como resultado.
     * @return Un objeto del tipo especificado en returnType.
     */
    public <T> T process(Function<TokenResponseModel, T> processor, Class<T> returnType) {
        return processor.apply(this);
    }
}


