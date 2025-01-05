package cu.entalla.service;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.store.AuthenticationStore;
import org.springframework.stereotype.Service;

@Service
public class UserService /*implements ContentModelInterface*/ {


    /*private final PersonService personService;
    private final ServiceRegistry serviceRegistry;*/

    private final Wso2SecurityConfig conf;

    /*public UserService(ServiceRegistry serviceRegistry) {
        this.serviceRegistry = serviceRegistry;
        this.personService = serviceRegistry.getPersonService();
        this.conf=  AuthenticationStore.getInstance().getWso2SecurityConfig();
    }*/
    public UserService() {
        this.conf=  AuthenticationStore.getInstance().getWso2SecurityConfig();
        //this.serviceRegistry = conf.serviceRegistry();
       // this.personService = serviceRegistry.getPersonService();
    }

    /**
     * Autentica un usuario previamente autenticado en WSO2 Identity Server
     * en Alfresco y/o Share.
     *
     * @param username Nombre del usuario
     * @param email Correo electrónico del usuario
     * @param phone Teléfono del usuario
     */
    // Autenticar usuario en Alfresco
    /*@Override
    public void authenticateUser(String username, String email, String phone) {
        // Verificar si el usuario ya existe
        if (!personService.personExists(username)) {
            // Crear un nuevo usuario en Alfresco si no existe
            Map<QName, Serializable> properties = new HashMap<>();
            properties.put(ContentModel.PROP_USERNAME, username);
            properties.put(ContentModel.PROP_EMAIL, email);
            properties.put(ContentModel.PROP_TELEPHONE, phone);
            properties.put(ContentModel.PROP_FIRSTNAME, username); // Placeholder para nombre
            properties.put(ContentModel.PROP_LASTNAME, "Usuario Autenticado"); // Placeholder para apellido
            createUser(properties);
        }
        else{
            // Actualizar las propiedades del usuario existente
            NodeRef personNodeRef = personService.getPerson(username);

            Map<QName, Serializable> updatedProperties = new HashMap<>();
            if (email != null && !email.isEmpty()) {
                updatedProperties.put(ContentModel.PROP_EMAIL, email);
            }
            if (phone != null && !phone.isEmpty()) {
                updatedProperties.put(ContentModel.PROP_TELEPHONE, phone);
            }

            if (!updatedProperties.isEmpty()) {
                serviceRegistry.getNodeService().addProperties(personNodeRef, updatedProperties);
            }
        }
        // Establecer la sesión autenticada
        Authentication authentication = AuthenticationUtil.setFullyAuthenticatedUser(username);
    }

    public void authenticateUser(String username, String email, String phone,String accessToken,String refreshToken) throws IOException {
                authenticateUser(username,email,phone);
                //setShareSession(username,email,phone,accessToken,refreshToken);
    }
    public void setShareSession(String username, String email, String phone,String accessToken,String refreshToken) throws IOException {
          // Verificar si el usuario ya existe en Alfresco
        if (!personService.personExists(username)) {
            createUserInAlfresco(username, email,phone); // Crear usuario si no existe
        }

        // Establecer al usuario como autenticado en Alfresco
        // AuthenticationUtil.setFullyAuthenticatedUser(username);

        // Establecer el token en el contexto de Alfresco para que pueda ser utilizado
        storeTokenInAlfrescoSession(username, accessToken, refreshToken);

        // Si es necesario hacer alguna configuración adicional en Share (por ejemplo, para compartir la sesión),
        // configurar ShareSession de manera similar aquí.
        setShareSessionInShare(username, accessToken, refreshToken);
    }

    // Crear un nuevo usuario en Alfresco con las propiedades proporcionadas
    @Override
    public void createUser(Map<QName, Serializable> properties) {
        personService.createPerson(properties);
    }

    // Crear una nueva sesión Alfresco usando OAuth2AuthenticationToken
    @Override
    public String createAlfrescoSession(OAuth2AuthenticationToken authentication) {
        // Obtener datos del usuario desde el token OAuth2
        String username = authentication.getPrincipal().getAttribute("username");
        String email = authentication.getPrincipal().getAttribute("email");
        String phone = authentication.getPrincipal().getAttribute("phone_number");

        // Autenticar o crear usuario en Alfresco
        authenticateUser(username, email, phone);
        try {
            setShareSession(authentication);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return "Sesión creada satisfactoriamente para el usuario: " + username;
    }*/

    /**
     * Crea un usuario en Alfresco con los atributos proporcionados.
     *
     * @param username Nombre del usuario
     * @param email Correo electrónico del usuario
     * @param phone Teléfono del usuario
     */
   /* private void createUserInAlfresco(String username, String email, String phone) {
        Map<QName, Serializable> properties = new HashMap<>();
        properties.put(ContentModel.PROP_USERNAME, username); // Nombre de usuario
        properties.put(ContentModel.PROP_EMAIL, email);       // Correo electrónico
        properties.put(ContentModel.PROP_TELEPHONE, phone);   // Teléfono
        properties.put(ContentModel.PROP_FIRSTNAME, username); // Nombre predeterminado
        properties.put(ContentModel.PROP_LASTNAME, "Usuario"); // Apellido predeterminado

        personService.createPerson(properties);

        System.out.println("Usuario " + username + " creado en Alfresco.");
    }*/

    /**
     * Establece la sesión o token en Share si se requiere
     * integración adicional entre Alfresco y Share.
     *
     * @param authentication Nombre del usuario autenticado
     */
    // Método para configurar la sesión de Alfresco y Share con los datos de OAuth2
   /* public void setShareSession(OAuth2AuthenticationToken authentication) throws IOException {
        // Extraer el access_token y refresh_token de los claims de WSO2 Identity Server
        String accessToken = (String) authentication.getPrincipal().getAttributes().get("access_token");//authentication.getTokenValue(); // token de acceso
        String refreshToken = (String) authentication.getPrincipal().getAttributes().get("refresh_token");

        // Obtener el username desde los atributos del token OAuth2
        String username = authentication.getPrincipal().getAttribute("username");
        String email = authentication.getPrincipal().getAttribute("email");
        String phone = authentication.getPrincipal().getAttribute("phone_number");
        // Verificar si el usuario ya existe en Alfresco
        if (!personService.personExists(username)) {
            createUserInAlfresco(username, email,phone); // Crear usuario si no existe
        }

        // Establecer al usuario como autenticado en Alfresco
       // AuthenticationUtil.setFullyAuthenticatedUser(username);

        // Establecer el token en el contexto de Alfresco para que pueda ser utilizado
        storeTokenInAlfrescoSession(username, accessToken, refreshToken);

        // Si es necesario hacer alguna configuración adicional en Share (por ejemplo, para compartir la sesión),
        // configurar ShareSession de manera similar aquí.
        setShareSessionInShare(username, accessToken, refreshToken);
    }
    // Almacenar el token de acceso y el refresh token en la sesión de Alfresco
    private void storeTokenInAlfrescoSession(String username, String accessToken, String refreshToken) {
        // Obtener el nodo de usuario correspondiente a partir del nombre de usuario
        NodeRef personNode = personService.getPerson(username);

        if (personNode == null) {
            throw new IllegalArgumentException("El usuario " + username + " no existe en Alfresco.");
        }

        // Crear un mapa de propiedades para almacenar los tokens
        Map<QName, Serializable> properties = new HashMap<>();
        properties.put(QName.createQName("http://www.alfresco.org/model/system/1.0", "access_token"), accessToken);
        properties.put(QName.createQName("http://www.alfresco.org/model/system/1.0", "refresh_token"), refreshToken);

        // Añadir un aspecto al nodo de usuario para almacenar los tokens
        serviceRegistry.getNodeService().addAspect(personNode, QName.createQName("http://www.alfresco.org/model/system/1.0", "authenticationTokens"), properties);

        // Guardar los cambios
        serviceRegistry.getNodeService().setProperties(personNode, properties);
    }

    // Método para configurar la sesión en Share
    private void setShareSessionInShare(String username, String accessToken, String refreshToken) throws IOException {
        // Aquí asumimos que la autenticación en Share se realiza a través de cookies o sesiones HTTP.

        // Crear un identificador único para la sesión (puede ser el username o algún otro identificador)
        String sessionId = "share-session-" + username;

        // Usar una librería para gestionar cookies, o si estás utilizando una API de Share para autenticar, hacerlo aquí
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();

        jakarta.servlet.http.HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        // Crear una cookie para almacenar el access_token
        Cookie accessTokenCookie = new Cookie("access_token", accessToken);
        accessTokenCookie.setPath("/"); // Asegúrate de que la cookie sea accesible desde todas las rutas de Share
        accessTokenCookie.setMaxAge(60 * 60); // Expira en una hora, puedes ajustarlo según tus necesidades
        response.addCookie(accessTokenCookie);

        // Crear una cookie para almacenar el refresh_token (opcional, si es necesario)
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setPath("/"); // Asegúrate de que la cookie sea accesible desde todas las rutas de Share
        refreshTokenCookie.setMaxAge(60 * 60); // Expira en una hora
        response.addCookie(refreshTokenCookie);

        // Establecer la sesión del usuario en Share (esto dependerá de cómo Share gestiona la autenticación)
        // En este caso, podemos utilizar la sesión HTTP para mantener al usuario autenticado
        HttpSession session = request.getSession();
        session.setAttribute("username", username);  // Establecer el nombre de usuario
        session.setAttribute("access_token", accessToken); // Almacenar el access_token
        session.setAttribute("refresh_token", refreshToken); // Almacenar el refresh_token

        // Opcional: Redirigir al usuario a la página principal de Share o a un lugar seguro
        response.sendRedirect("/share/page/dashboards");
    }*/
}
