package cu.entalla.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import cu.entalla.loader.LocalJWKSetLoader;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

@Data
@AllArgsConstructor
public class JwtConfig {

    @Value("oauth2.client.provider.wso2.public-key")
    private String publicKeyPath = "/path/to/public_key.pem";  // Ruta del archivo PEM de la clave pública

    @Value("oauth2.client.registration.wso2.private-key")
    private String privateKeyPath = "/path/to/private_key.pem";  // Ruta del archivo PEM de la clave privada

    public JwtConfig(){
        Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create();
        if(!wso2SecurityConfig.isLoaded())
            wso2SecurityConfig.loadProperties();
        this.publicKeyPath=wso2SecurityConfig.getPropertyByKey("oauth2.client.provider.wso2.public-key",publicKeyPath);
        this.privateKeyPath=wso2SecurityConfig.getPropertyByKey("oauth2.client.registration.wso2.private-key",privateKeyPath);
    }

    public PublicKey loadPublicKey() throws Exception {
        // Leer el archivo PEM
        try (PEMParser pemParser = new PEMParser(new FileReader(publicKeyPath))) {
            Object object = pemParser.readObject();

            // Convertir el objeto al tipo PublicKey
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            // El archivo PEM puede contener diferentes tipos de objetos (certificados, claves públicas, etc.)
            if (object instanceof org.bouncycastle.cert.X509CertificateHolder) {
                // Si el archivo contiene un certificado
                return converter.getPublicKey(((org.bouncycastle.cert.X509CertificateHolder) object).getSubjectPublicKeyInfo());
            } else if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                // Si el archivo contiene directamente la clave pública
                return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
            } else {
                throw new IllegalArgumentException("El archivo no contiene una clave pública válida.");
            }
        }
    }

    // Método para cargar la clave pública desde un archivo PEM
    public PublicKey loadPublicKey(String publicKeyPath) throws Exception {
        // Leer el archivo PEM
        try (PEMParser pemParser = new PEMParser(new FileReader(publicKeyPath))) {
            Object object = pemParser.readObject();

            // Convertir el objeto al tipo PublicKey
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            // El archivo PEM puede contener diferentes tipos de objetos (certificados, claves públicas, etc.)
            if (object instanceof org.bouncycastle.cert.X509CertificateHolder) {
                // Si el archivo contiene un certificado
                return converter.getPublicKey(((org.bouncycastle.cert.X509CertificateHolder) object).getSubjectPublicKeyInfo());
            } else if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                // Si el archivo contiene directamente la clave pública
                return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
            } else {
                throw new IllegalArgumentException("El archivo no contiene una clave pública válida.");
            }
        }
    }

    public
    PrivateKey loadPrivateKey() throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
            Object object = pemParser.readObject();
            // Convertir el objeto al tipo PrivateKey
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
        }
    }
    // Método para cargar la clave privada desde un archivo PEM
    public PrivateKey loadPrivateKey(String privateKeyPath) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
            Object object = pemParser.readObject();
            // Convertir el objeto al tipo PrivateKey
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
        }
    }

    public JwtDecoder jwtDecoder() throws Exception {
        // Cargar clave pública y privada desde archivos PEM
        PublicKey publicKey = loadPublicKey(publicKeyPath);
        PrivateKey privateKey = loadPrivateKey(privateKeyPath);

        // Crear un procesador JWT
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Configurar un JWK source
        JWKSource<SecurityContext> jwkPublicSource =new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return getJWKSet(securityContext).getKeys();
            }
           public JWKSet getJWKSet(SecurityContext context)  {
                try {
                    return new LocalJWKSetLoader().loadJWKSetFromFile(publicKeyPath);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        JWKSource<SecurityContext> jwkPrivateSource =new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
                return getJWKSet(securityContext).getKeys();
            }
            public JWKSet getJWKSet(SecurityContext context)  {
                try {
                    return new LocalJWKSetLoader().loadJWKSetFromFile(privateKeyPath);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        // Configurar el descifrador JWE (Encrypted JWT) con la clave privada
        JWEDecryptionKeySelector<SecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, jwkPrivateSource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        // Configurar la verificación de firma JWS usando la clave pública
        JWSVerificationKeySelector<SecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkPublicSource); // Ahora usamos RSAPublicKey directamente
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        return new NimbusJwtDecoder(jwtProcessor);
    }
}
