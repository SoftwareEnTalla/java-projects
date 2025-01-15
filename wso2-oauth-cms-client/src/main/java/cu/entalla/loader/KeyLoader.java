package cu.entalla.loader;
import cu.entalla.config.Wso2SecurityConfig;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class KeyLoader {

    static {
        // Asegúrate de registrar el proveedor de BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
    }
    private static final Logger logger = Logger.getLogger(KeyLoader.class.getName());
    // Método para cargar la clave privada
    public static PrivateKey loadPrivateKey(String privateKeyPath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
            Object object = pemParser.readObject();
            // Imprimir el objeto leído para ver qué contiene
            logger.info("===========================Objeto leído: " + object+" ===================================");
            // Verificar si el objeto es una clave privada (PKCS8)
            if (object instanceof java.security.PrivateKey) {
                return (PrivateKey) object;
            }
            if (object instanceof RSAPrivateKey) {
                return (RSAPrivateKey) object; // Retorna la clave RSA directamente
            }else {
                throw new IOException("El archivo "+privateKeyPath+" no contiene una clave privada válida.");
            }
        }
    }

    public static String extractPrivateKey(String pemFilePath) throws IOException {
        // Leer todo el contenido del archivo PEM
        String pemContent = new String(Files.readAllBytes(Paths.get(pemFilePath)), "UTF-8");

        // Buscar la parte que está entre -----BEGIN PRIVATE KEY----- y -----END PRIVATE KEY-----
        String privateKey = null;

        if (pemContent.contains("-----BEGIN PRIVATE KEY-----") && pemContent.contains("-----END PRIVATE KEY-----")) {
            int beginIndex = pemContent.indexOf("-----BEGIN PRIVATE KEY-----") + "-----BEGIN PRIVATE KEY-----".length();
            int endIndex = pemContent.indexOf("-----END PRIVATE KEY-----");

            // Extraer la clave privada en base64 sin las cabeceras y pies de clave
            privateKey = pemContent.substring(beginIndex, endIndex).trim();
        } else {
            throw new IOException("El archivo " + pemFilePath + " no contiene una clave privada válida.");
        }

        // Eliminar saltos de línea y espacios (debe estar en formato base64 limpio)
        return privateKey.replaceAll("\\s", "");
    }

    // Extraer la clave privada de un archivo PEM y devolverla como PrivateKey
    public static PrivateKey getPrivateKey(String pemFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Leer el contenido del archivo PEM
        String privateKeyContent = extractPrivateKey(pemFilePath);

        // Convertir la clave privada Base64 en bytes
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);

        // Crear la clave privada a partir de los bytes
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  // Asegúrate de que el algoritmo coincida con tu clave
        return keyFactory.generatePrivate(keySpec);
    }
    public static PKCS8EncodedKeySpec getPKCS8EncodedKeySpec(String privateKeyPath) throws IOException {
        PrivateKey privateKey = loadPrivateKey(privateKeyPath);
        // Decodificar la cadena Base64 a un arreglo de bytes
        byte[] decodedKey = privateKey.getEncoded();
        // Crear un objeto PKCS8EncodedKeySpec
        return new PKCS8EncodedKeySpec(decodedKey);
    }

    // Método para cargar la clave pública
    public static PublicKey loadPublicKey(String publicKeyPath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(publicKeyPath))) {
            Object object = pemParser.readObject();

            // Verificar si el objeto es una clave pública
            if (object instanceof java.security.PublicKey) {
                return (PublicKey) object;
            } else {
                throw new IOException("El archivo "+publicKeyPath+" no contiene una clave pública válida.");
            }
        }
    }
    public static PublicKey getPublicKey(String pemFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        // Leer el contenido del archivo PEM
        String publicKeyContent = extractPublicKey(pemFilePath);

        // Convertir el certificado Base64 en bytes
        byte[] certBytes = Base64.getDecoder().decode(publicKeyContent);

        // Crear el certificado desde los bytes
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        // Extraer la clave pública del certificado
        return certificate.getPublicKey();
    }

    // Extraer el certificado público de un archivo PEM y devolverlo como una cadena Base64
    private static String extractPublicKey(String pemFilePath) throws IOException {
        String pemContent = new String(Files.readAllBytes(Paths.get(pemFilePath)), "UTF-8");

        // Buscar el contenido entre las palabras clave -----BEGIN CERTIFICATE----- y -----END CERTIFICATE-----
        if (pemContent.contains("-----BEGIN CERTIFICATE-----") && pemContent.contains("-----END CERTIFICATE-----")) {
            int beginIndex = pemContent.indexOf("-----BEGIN CERTIFICATE-----") + "-----BEGIN CERTIFICATE-----".length();
            int endIndex = pemContent.indexOf("-----END CERTIFICATE-----");
            String publicKey = pemContent.substring(beginIndex, endIndex).trim();
            return publicKey.replaceAll("\\s", "");  // Eliminar espacios y saltos de línea
        } else {
            throw new IOException("El archivo " + pemFilePath + " no contiene un certificado válido.");
        }
    }
    public static void main(String[] args) {
        try {
            String privateKeyPath = "/path/to/your/private_key.pem"; // Ruta de la clave privada
            String publicKeyPath = "/path/to/your/public_key.pem"; // Ruta de la clave pública

            // Cargar la clave privada
            PrivateKey privateKey = loadPrivateKey(privateKeyPath);
            System.out.println("Clave privada cargada correctamente: " + privateKey);

            // Cargar la clave pública
            PublicKey publicKey = loadPublicKey(publicKeyPath);
            System.out.println("Clave pública cargada correctamente: " + publicKey);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

