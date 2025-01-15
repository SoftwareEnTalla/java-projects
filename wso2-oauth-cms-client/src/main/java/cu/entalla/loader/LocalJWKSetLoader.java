package cu.entalla.loader;

import com.nimbusds.jose.jwk.JWKSet;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.URL;

public class LocalJWKSetLoader {

    /**
     * Carga un JWKSet desde un archivo local.
     *
     * @param filePath Ruta al archivo JWK (archivo .json).
     * @return JWKSet cargado.
     * @throws Exception Si ocurre un error al leer o procesar el archivo.
     */
    public JWKSet loadJWKSetFromFile(String filePath) throws Exception {
        // Leer el archivo JWK desde la ruta proporcionada
        InputStream jwkStream = Files.newInputStream(Paths.get(filePath));
        return JWKSet.load(jwkStream);
    }

    /**
     * Carga un JWKSet desde el classpath.
     *
     * @param classpathResource Ruta al recurso en el classpath (archivo .json).
     * @return JWKSet cargado.
     * @throws Exception Si ocurre un error al leer o procesar el archivo.
     */
    public JWKSet loadJWKSetFromClasspath(String classpathResource) throws Exception {
        // Leer el archivo JWK desde el classpath
        InputStream jwkStream = getClass().getResourceAsStream(classpathResource);
        if (jwkStream == null) {
            throw new IllegalArgumentException("Recurso no encontrado en el classpath: " + classpathResource);
        }
        return JWKSet.load(jwkStream);
    }

    public static void main(String[] args) {
        try {
            LocalJWKSetLoader loader = new LocalJWKSetLoader();

            // Cargar desde un archivo local
            JWKSet jwkSetLocal = loader.loadJWKSetFromFile("path/to/your/jwks.json");
            System.out.println("JWKSet cargado desde archivo local");

            // Cargar desde el classpath
            JWKSet jwkSetClasspath = loader.loadJWKSetFromClasspath("/resources/jwks.json");
            System.out.println("JWKSet cargado desde classpath");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
