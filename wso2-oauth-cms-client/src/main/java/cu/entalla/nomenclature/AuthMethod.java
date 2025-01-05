package cu.entalla.nomenclature;


public enum AuthMethod {

    CLIENT_SECRET_POST("client_secret_post"),
    CLIENT_SECRET_BASIC("client_secret_basic"),
    CLIENT_SECRET_JWT("client_secret_jwt"),
    PRIVATE_KEY_JWT("private_key_jwt"),

    TLS_CLIENT_AUTH("tls_client_auth"),
    PKCE("pkce");

    private final String method;

    // Constructor
    AuthMethod(String method) {
        this.method = method;
    }

    // Método para obtener el valor de la cadena asociada al tipo de autenticación
    public String getMethod() {
        return method;
    }

    // Método estático para obtener el enumerador a partir de una cadena
    public static AuthMethod fromString(String method) {
        for (AuthMethod authMethod : AuthMethod.values()) {
            if (authMethod.getMethod().equalsIgnoreCase(method)) {
                return authMethod;
            }
        }
        throw new IllegalArgumentException("No such authentication method: " + method);
    }

    @Override
    public String toString() {
        return method;
    }
}