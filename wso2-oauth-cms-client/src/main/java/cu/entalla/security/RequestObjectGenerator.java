package cu.entalla.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

public class RequestObjectGenerator {

    private static final Logger logger = Logger.getLogger(RequestObjectGenerator.class.getName());
    public static String getJWTfromFile(String clientId,String authorizationUrl,String redirectUri,String privateKeyFile,String codeChallenge) {
        try {
            // Ruta del archivo PEM que contiene la clave privada
            // "/media/datos/Instaladores/entalla/wso2is-7.0.0/repository/resources/security/softwarentalla-priv-key.pem"
            Path privateKeyPath = Paths.get(privateKeyFile);

            // Leer el contenido del archivo PEM
            String privateKeyPem = Files.readString(privateKeyPath);

            // Convertir clave privada en formato PrivateKey
            PrivateKey privateKey = loadPrivateKey(privateKeyPem);

            long now = System.currentTimeMillis();
            String jwt = Jwts.builder()
                    .setIssuer(clientId)
                    .setAudience(authorizationUrl)
                    .setExpiration(new Date(now + 5 * 60 * 1000)) // 5 minutos
                    .setIssuedAt(new Date(now))
                    .setId(UUID.randomUUID().toString())
                    .claim("response_type", "code")
                    .claim("client_id", clientId)
                    .claim("redirect_uri", redirectUri)
                    .claim("scope", "openid address email phone profile")
                    .claim("code_challenge", codeChallenge)
                    .claim("code_challenge_method", "S256")
                    .signWith(SignatureAlgorithm.RS256,privateKey)
                    .compact();

            logger.info("Request Object (JWT): " + jwt);
            return jwt;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static PrivateKey loadPrivateKey(String privateKeyPem) throws Exception {
        String privateKeyContent = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
