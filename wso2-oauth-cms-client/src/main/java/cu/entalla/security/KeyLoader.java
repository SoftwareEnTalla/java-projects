package cu.entalla.security;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class KeyLoader {

    public static PrivateKey loadPrivateKey() throws Exception {
        // Ruta al archivo PEM de la clave privada
        String privateKeyPath = "/media/datos/Instaladores/entalla/wso2is-7.0.0/repository/resources/security/softwarentalla-priv-key.pem";

        // Leer el contenido del archivo
        String privateKeyContent = readFile(privateKeyPath);

        // Eliminar encabezado, pie y caracteres de nueva línea
        privateKeyContent = privateKeyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // Decodificar la clave en formato PKCS#8
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);

        // Crear una especificación de clave privada
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Instanciar el KeyFactory para RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generar y devolver la clave privada
        return keyFactory.generatePrivate(keySpec);
    }

    private static String readFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (FileReader reader = new FileReader(new File(filePath))) {
            int ch;
            while ((ch = reader.read()) != -1) {
                content.append((char) ch);
            }
        }
        return content.toString();
    }
}
