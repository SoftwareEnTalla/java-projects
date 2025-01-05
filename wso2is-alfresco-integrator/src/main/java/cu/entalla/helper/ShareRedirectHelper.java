package cu.entalla.helper;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.UUID;

public class ShareRedirectHelper {

    /**
     * Configura cookies, headers y redirecciona hacia Share.
     *
     * @param response    HttpServletResponse para configurar las cookies y cabeceras.
     * @param username    Nombre del usuario autenticado.
     * @param ticket      Ticket generado para Alfresco.
     * @param shareHost   URL base de Share (ej: https://ses-cms.entalla.cu:8443).
     * @param shareContext Contexto de Share (ej: "share").
     */
    public static void configureAndRedirectToShare(HttpServletResponse response, String username, String ticket, String shareHost, String shareContext) {
        try {
            // Configurar cookies
            setCookie(response, "Alfresco-Ticket", ticket, "/share", 604800); // 7 días
            setCookie(response, "Alfresco-CSRFToken", generateCSRFToken(), "/share", 604800); // 7 días
            setCookie(response, "alfLogin", String.valueOf(System.currentTimeMillis() / 1000), "/share", 604800); // Login timestamp
            setCookie(response, "alfUsername3", username, "/share", 604800); // Nombre de usuario

            // Configurar cabeceras
            response.setHeader("Cache-Control", "no-cache");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("X-Content-Type-Options", "nosniff");
            response.setHeader("X-Frame-Options", "SAMEORIGIN");
            response.setHeader("X-XSS-Protection", "1; mode=block");
            response.setHeader("Content-Language", "es-ES");

            // Redirigir hacia el dashboard del usuario en Share
            String redirectUrl = shareHost + "/" + shareContext + "/page/user/" + username + "/dashboard";
            response.sendRedirect(redirectUrl);
        } catch (Exception e) {
            throw new RuntimeException("Error configuring and redirecting to Share", e);
        }
    }

    /**
     * Crea y añade una cookie al HttpServletResponse.
     *
     * @param response HttpServletResponse para añadir la cookie.
     * @param name     Nombre de la cookie.
     * @param value    Valor de la cookie.
     * @param path     Path válido para la cookie.
     * @param maxAge   Duración máxima en segundos.
     */
    private static void setCookie(HttpServletResponse response, String name, String value, String path, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath(path);
        cookie.setMaxAge(maxAge);
        cookie.setHttpOnly(true); // Opcional: Protege contra ataques XSS
        cookie.setSecure(true); // Opcional: Requiere HTTPS
        response.addCookie(cookie);
    }

    /**
     * Genera un token CSRF único.
     *
     * @return Token único como String.
     */
    private static String generateCSRFToken() {
        return UUID.randomUUID().toString();
    }

    public static void doLoginToShare(HttpServletResponse response, String username, String password, String shareHost, String shareContext) {
        try {
            // Construir la URL del endpoint doLogin
            String loginUrl = shareHost + "/" + shareContext + "/page/dologin";

            // Preparar datos del formulario
            String successUrl = "/share/page/";
            String failureUrl = "/share/page/?error=true";
            String postData = "success=" + URLEncoder.encode(successUrl, "UTF-8") +
                    "&failure=" + URLEncoder.encode(failureUrl, "UTF-8") +
                    "&username=" + URLEncoder.encode(username, "UTF-8") +
                    "&password=" + URLEncoder.encode(password, "UTF-8");

            // Crear la conexión HTTP
            URL url = new URL(loginUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "*/*");

            // Enviar datos POST
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.getBytes("UTF-8"));
            }

            // Leer cookies de respuesta para agregarlas al cliente
            String setCookieHeader = conn.getHeaderField("Set-Cookie");
            if (setCookieHeader != null) {
                String[] cookies = setCookieHeader.split(";");
                for (String cookie : cookies) {
                    String[] cookiePair = cookie.split("=");
                    if (cookiePair.length == 2) {
                        Cookie newCookie = new Cookie(cookiePair[0], cookiePair[1]);
                        newCookie.setPath("/share");
                        newCookie.setMaxAge(604800); // 7 días
                        response.addCookie(newCookie);
                    }
                }
            }

            // Configurar la redirección tras el login
            if (conn.getResponseCode() == 302) {
                String location = conn.getHeaderField("Location");
                if (location != null) {
                    response.sendRedirect(location);
                } else {
                    throw new RuntimeException("No se encontró la ubicación de redirección en la respuesta de doLogin.");
                }
            } else {
                throw new RuntimeException("Error en doLogin. Código HTTP: " + conn.getResponseCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error al realizar doLogin en Share.", e);
        }
    }
}
