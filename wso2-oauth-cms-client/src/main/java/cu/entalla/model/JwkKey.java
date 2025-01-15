package cu.entalla.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Data;

import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.util.Base64;

@Data
public class JwkKey {

    /**
     * Key type (e.g., "RSA", "EC").
     */
    @JsonProperty("kty")
    private String keyType;

    /**
     * SHA-256 thumbprint of the X.509 certificate.
     */
    @JsonProperty("x5t#S256")
    private String thumbprint;

    /**
     * The modulus value used in RSA keys.
     */
    @JsonProperty("n")
    private String modulus;

    /**
     * Exponent value used in RSA keys (e.g., "AQAB").
     */
    @JsonProperty("e")
    private String exponent;

    /**
     * Intended use of the key (e.g., "sig" for signing).
     */
    @JsonProperty("use")
    private String use;

    /**
     * Key identifier, a unique identifier for the key.
     */
    @JsonProperty("kid")
    private String keyId;

    /**
     * The X.509 certificate chain associated with the key.
     */
    @JsonProperty("x5c")
    private String[] certificateChain;

    /**
     * Algorithm intended for the key (e.g., "RS256").
     */
    @JsonProperty("alg")
    private String algorithm;

    @JsonProperty("use")
    public String getUse() {
        return this.use;
    }

    public String toString() {
        return "JwkKey{" +
                "keyId='" + keyId + '\'' +
                ", keyType='" + keyType + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", use='" + use + '\'' +
                ", modulus='" + modulus + '\'' +
                ", exponent='" + exponent + '\'' +
                '}';
    }

    public RSAPublicKey toRSAPublicKey() throws Exception {
        // Decodificar los valores Base64 a byte[].
        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);
        // Asegúrate de que los campos 'n' (modulus) y 'e' (exponent) estén presentes en el JwkKey
        BigInteger modulus = new BigInteger(1, modulusBytes);  // getN() devuelve el módulo (n) de la clave
        BigInteger publicExponent = new BigInteger(1, exponentBytes);  // getE() devuelve el exponente público (e)

        // Crear una especificación de la clave pública RSA utilizando el módulo y el exponente
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);

        // Usar KeyFactory para generar el RSAPublicKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public JwtAlgorithmConfig toJwtAlgorithmConfig() {
        JwtAlgorithmConfig config = new JwtAlgorithmConfig();

        // Asignar el algoritmo de firma basado en el campo 'alg' de JwkKey.
        if (this.algorithm != null) {
            switch (this.algorithm) {
                case "RS256":
                    config.setJwsAlgorithm(JWSAlgorithm.RS256);
                    break;
                case "RS384":
                    config.setJwsAlgorithm(JWSAlgorithm.RS384);
                    break;
                case "RS512":
                    config.setJwsAlgorithm(JWSAlgorithm.RS512);
                    break;
                case "HS256":
                    config.setJwsAlgorithm(JWSAlgorithm.HS256);
                    break;
                case "HS384":
                    config.setJwsAlgorithm(JWSAlgorithm.HS384);
                    break;
                case "HS512":
                    config.setJwsAlgorithm(JWSAlgorithm.HS512);
                    break;
                case "ES256":
                    config.setJwsAlgorithm(JWSAlgorithm.ES256);
                    break;
                case "ES384":
                    config.setJwsAlgorithm(JWSAlgorithm.ES384);
                    break;
                case "ES512":
                    config.setJwsAlgorithm(JWSAlgorithm.ES512);
                    break;
                case "DS256":
                    config.setJwsAlgorithm(JWSAlgorithm.parse(algorithm));  // DSA con SHA-256
                    break;

                default:
                    config.setJwsAlgorithm(JWSAlgorithm.parse(algorithm));  // DSA con SHA-256
                    break;
            }
        }

        // Asignar el algoritmo de cifrado (JWE) basado en el tipo de clave.
        if (this.keyType != null) {
            switch (this.keyType) {
                case "RSA":
                    // Usar RSA para cifrado (JWE)
                    config.setJweAlgorithm(JWEAlgorithm.RSA_OAEP_256);
                    break;
                case "EC":
                    // Usar EC para cifrado (JWE)
                    config.setJweAlgorithm(JWEAlgorithm.ECDH_ES_A256KW);
                    break;
                case "oct":
                    // Algoritmo simétrico para cifrado (JWE)
                    config.setJweAlgorithm(JWEAlgorithm.DIR);
                    break;
                case "DSA":
                    // No es común usar DSA para JWE (cifrado), pero podrías implementarlo con otro algoritmo si lo necesitas
                    config.setJweAlgorithm(JWEAlgorithm.parse(keyType));  // DSA no es comúnmente usado para JWE
                    break;
                default:
                    config.setJweAlgorithm(JWEAlgorithm.parse(keyType));  // DSA no es comúnmente usado para JWE
                    break;
            }
        }

        // Asignar el método de cifrado basado en el tipo de clave.
        if (this.algorithm != null) {
            switch (this.algorithm) {
                case "RS256":
                case "RS384":
                case "RS512":
                    // Métodos de cifrado para RSA
                    config.setEncryptionMethod(EncryptionMethod.A128GCM);
                    break;
                case "HS256":
                case "HS384":
                case "HS512":
                    // Métodos de cifrado para HMAC (algoritmos simétricos)
                    config.setEncryptionMethod(EncryptionMethod.A128CBC_HS256);
                    break;
                case "ES256":
                case "ES384":
                case "ES512":
                    // Métodos de cifrado para EC (Elliptic Curve)
                    config.setEncryptionMethod(EncryptionMethod.A128GCM);
                    break;
                case "oct":
                    // Cifrado simétrico
                    config.setEncryptionMethod(EncryptionMethod.A128CBC_HS256);
                    break;
                case "DS256":
                case "DS384":
                case "DS512":
                    // Métodos de cifrado para DSA
                    config.setEncryptionMethod(EncryptionMethod.parse(algorithm)); // DSA no se usa para cifrado, sino para firma
                    break;
                default:
                    config.setEncryptionMethod(EncryptionMethod.parse(algorithm)); // DSA no se usa para cifrado, sino para firma
                    break;
            }
        }

        return config;
    }
}