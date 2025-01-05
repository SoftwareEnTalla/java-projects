package cu.entalla.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.service.AuthenticationService;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.logging.Logger;

@AllArgsConstructor
@Getter
public class AccessTokenValidator {

    private static final Logger logger = Logger.getLogger(AccessTokenValidator.class.getName());

    public static PublicKey extractPublicKeyFromPEM(String pemFilePath) throws Exception {
        // Crear una instancia de CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Leer el archivo PEM
        try (FileInputStream pemFile = new FileInputStream(pemFilePath)) {
            // Cargar el certificado X.509
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(pemFile);

            // Obtener la clave pública del certificado
            return certificate.getPublicKey();
        }
    }
    public static PublicKey extractPublicKeyFromPEM(File pemFilePath) throws Exception {
        // Crear una instancia de CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Leer el archivo PEM
        try (FileInputStream pemFile = new FileInputStream(pemFilePath)) {
            // Cargar el certificado X.509
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(pemFile);

            // Obtener la clave pública del certificado
            return certificate.getPublicKey();
        }
    }
    public  static RSAPrivateKey loadPrivateKey(String pemFile) throws Exception {
        // Asegúrate de registrar el proveedor de BouncyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Abre el archivo PEM
        PEMParser pemParser = new PEMParser(new FileReader(pemFile));
        Object object = pemParser.readObject();
        pemParser.close();

        if (object instanceof PEMKeyPair) {
            PEMKeyPair keyPair = (PEMKeyPair) object;
            PrivateKeyInfo privateKeyInfo = keyPair.getPrivateKeyInfo();

            // Convierte la PrivateKeyInfo a un array de bytes
            byte[] privateKeyBytes = privateKeyInfo.getEncoded();

            // Utiliza KeyFactory con un PKCS8EncodedKeySpec para generar la clave privada
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
        else if(object instanceof PrivateKeyInfo){
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo)object;

            // Convierte la PrivateKeyInfo a un array de bytes
            byte[] privateKeyBytes = privateKeyInfo.getEncoded();

            // Utiliza KeyFactory con un PKCS8EncodedKeySpec para generar la clave privada
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
        else {
            throw new IOException("El archivo no contiene una clave privada válida.");
        }
    }


    // Método para validar la firma con la clave pública
    public static boolean validateSignature(String accessToken, String publicKey) {
        try {
            //JWT jwt = JWTParser.parse(accessToken);
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            RSASSAVerifier verifier = new RSASSAVerifier(loadPublicKey(publicKey));
            return verifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(),signedJWT.getSignature());
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    // Método para validar la firma con la clave pública
    public static boolean validateSignature(String accessToken, RSAPublicKey publicKey) {
        try {
            //JWT jwt = JWTParser.parse(accessToken);
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
            return verifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(),signedJWT.getSignature());
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // Método para cargar la clave pública desde un archivo PEM
    public static RSAPublicKey loadPublicKey(String pemFilePath) {
        try (FileInputStream fis = new FileInputStream(pemFilePath)) {
            // Cargar clave pública desde un archivo PEM (depende de cómo la obtengas)
            JWK jwk = JWK.parseFromPEMEncodedObjects(fis.toString());
            return (RSAPublicKey) jwk.toECKey().toPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String publicKeyToString(RSAPublicKey publicKey) {
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n";
        publicKeyPEM += Base64.getEncoder().encodeToString(publicKey.getEncoded());
        publicKeyPEM += "\n-----END PUBLIC KEY-----";
        return publicKeyPEM;
    }
    public static String privateKeyToString(RSAPrivateKey privateKey) {
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n";
        privateKeyPEM += Base64.getEncoder().encodeToString(privateKey.getEncoded());
        privateKeyPEM += "\n-----END PRIVATE KEY-----";
        return privateKeyPEM;
    }
    public String getPrivateKey(String pemFilePath) {
        try (FileInputStream fis = new FileInputStream(pemFilePath)) {
            // Cargar clave pública desde un archivo PEM (depende de cómo la obtengas)
            JWK jwk = JWK.parseFromPEMEncodedObjects(fis.toString());
            return  privateKeyToString(jwk.toRSAKey().toRSAPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String getPublicKey(String pemFilePath) {
        try (FileInputStream fis = new FileInputStream(pemFilePath)) {
            // Cargar clave pública desde un archivo PEM (depende de cómo la obtengas)
            JWK jwk = JWK.parseFromPEMEncodedObjects(fis.toString());
            return  publicKeyToString(jwk.toRSAKey().toRSAPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Método para decodificar el payload
    public static String decodeToken(String accessToken) {
        String payLoad = null;
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            payLoad = signedJWT.getPayload().toString();
            logger.info("Decoded JWT Payload: " + payLoad);
        } catch (ParseException e) {
            logger.severe("Error parsing JWT token: " + e.getMessage());
            e.printStackTrace();
        }
        return payLoad;
    }

    // Método para obtener el header del token
    public static Map<String, Object> getHeader(String accessToken) {
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            return signedJWT.getHeader().toJSONObject();
        } catch (ParseException e) {
            logger.severe("Error parsing JWT token: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    // Método para obtener la firma del token
    public static String getSignature(String accessToken) {
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            return signedJWT.getSignature().toString();
        } catch (ParseException e) {
            logger.severe("Error parsing JWT token: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    public static RSAPublicKey loadPublicKeyFromPEMString(String pemString) throws Exception {
        // Agregar el proveedor de BouncyCastle
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Crear un parser PEM para leer la cadena PEM
        PEMParser pemParser = new PEMParser(new StringReader(pemString));

        // Leer el objeto de la cadena PEM
        Object object = pemParser.readObject();
        pemParser.close();

        // Verificar si el objeto leído es una clave pública RSA
        if (object instanceof RSAPublicKey) {
            return (RSAPublicKey) object;
        }
        else if (object instanceof SubjectPublicKeyInfo) {
            // Convertir SubjectPublicKeyInfo a una clave pública RSAPublicKey
            // Obtener el SubjectPublicKeyInfo
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) object;

            // Obtener el encoded key y generar el RSAPublicKey a partir de ella
            byte[] encodedKey = publicKeyInfo.getEncoded();

            // Crear la clave pública RSA usando X509EncodedKeySpec
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            return rsaPublicKey;
        } else {
            throw new Exception("La cadena PEM no contiene una clave pública RSA válida.");
        }
    }

    // Método para validar la firma del JWT
    public static boolean validateSignature(String accessToken) {
        try {
            Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create();
            Wso2AuthenticatorClient client = Wso2AuthenticatorClient.create(wso2SecurityConfig.getGlobalPropertyFile());
            JWKSet jwkSet = AccessTokenValidator.fetchJwkSet(wso2SecurityConfig.getJwkSetUri(), client.getHttpClient());
            // Parsear el JWT
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            String kid = signedJWT.getHeader().getKeyID();
            // Buscar la clave pública correspondiente al KID
            JWK jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk == null) {
                System.err.println("No se encontró clave pública para el KID: " + kid);
                return false;
            }
            // Convertir el JWK a RSAPublicKey
            RSAPublicKey publicKey = jwk.toRSAKey().toRSAPublicKey();
            // Crear un verificador para RS256
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            // Validar la firma
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            logger.severe("Error validating JWT signature: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    // Método para verificar si el JWT ha expirado
    public static boolean isTokenExpired(String accessToken) {
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(accessToken);
            // Obtener el payload
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            // Obtener la fecha de expiración
            Date expirationDate = claims.getExpirationTime();
            // Verificar si la fecha de expiración es posterior a la fecha actual
            return expirationDate != null && expirationDate.before(new Date());
        } catch (ParseException e) {
            logger.severe("Error parsing JWT token: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    public static boolean isValidAccessToken(String accessToken){
        return accessToken!=null && !accessToken.isEmpty() && !isTokenExpired(accessToken) && validateSignature(accessToken);
    }
    // Método principal de prueba
    public static void main(String[] args) throws Exception {
        // Aquí debes poner tu JWT (token de acceso)

    }
    public static JWKSet fetchJwkSet(String jwksUri, HttpClient client) throws Exception {
        // Construir la solicitud
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(jwksUri))
                .GET()
                .build();
        // Enviar la solicitud y obtener la respuesta
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // Validar el código de estado
        if (response.statusCode() != 200) {
            throw new RuntimeException("Error al obtener el JWK Set: " + response.statusCode());
        }

        // Parsear el JWK Set desde la respuesta
        return JWKSet.parse(response.body());
    }
}

