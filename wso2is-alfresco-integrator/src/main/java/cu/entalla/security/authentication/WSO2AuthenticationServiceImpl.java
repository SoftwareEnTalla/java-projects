package cu.entalla.security.authentication;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.*;
import cu.entalla.client.Wso2AuthenticatorClient;
import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.service.ServiceLocator;
import cu.entalla.store.AuthenticationStore;
import cu.entalla.udi.ClientServiceIntegration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import net.sf.acegisecurity.Authentication;
import org.alfresco.repo.cache.DefaultSimpleCache;
import org.alfresco.repo.cache.TransactionalCache;
import org.alfresco.repo.dictionary.DictionaryComponent;
import org.alfresco.repo.policy.PolicyComponentImpl;
import org.alfresco.repo.security.authentication.*;
import org.alfresco.repo.security.authority.AuthorityDAOImpl;
import org.alfresco.repo.security.authority.AuthorityServiceImpl;
import org.alfresco.repo.security.permissions.impl.AllowPermissionServiceImpl;
import org.alfresco.repo.security.person.PersonServiceImpl;
import org.alfresco.repo.security.person.UserNameMatcherImpl;
import org.alfresco.repo.tenant.MultiTServiceImpl;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
import org.springframework.extensions.surf.exception.RequestContextException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;


@Component
public class WSO2AuthenticationServiceImpl extends AuthenticationServiceImpl implements MutableAuthenticationService {

    private String providerId;

    private PersonService personService;


    private AuthorityService authorityService;


    public PersonService getPersonService() {
        return personService;
    }

    public AuthorityService getAuthorityService() {
        return authorityService;
    }

    public MutableAuthenticationService getMutableAuthenticationService() {
        return mutableAuthenticationService;
    }

    private final MutableAuthenticationService mutableAuthenticationService=new MutableAuthenticationServiceImpl();
    private static final Logger logger = Logger.getLogger(WSO2AuthenticationServiceImpl.class.getName());

    private HttpSession session;
    private HttpServletRequest request;

    private HttpServletResponse response;

    public WSO2AuthenticationServiceImpl(String providerId) {
        super();
        this.providerId = providerId;
        personService=new PersonServiceImpl();
        authorityService=new AuthorityServiceImpl();
        if(authorityService instanceof AuthorityServiceImpl){
            ((AuthorityServiceImpl)authorityService).setPersonService(personService);
            ((AuthorityServiceImpl)authorityService).setAuthenticationService(this);
            ((AuthorityServiceImpl)authorityService).setTenantService(new MultiTServiceImpl());
            ((AuthorityServiceImpl)authorityService).setPolicyComponent(new PolicyComponentImpl(new DictionaryComponent()));
            ((AuthorityServiceImpl)authorityService).setAuthorityDAO(new AuthorityDAOImpl());
            ((AuthorityServiceImpl)authorityService).setUserNameMatcher(new UserNameMatcherImpl());
            //((AuthorityServiceImpl)authorityService).setPermissionServiceSPI(new AllowPermissionServiceImpl());
            ((AuthorityServiceImpl)authorityService).init();
        }
        logger.info("Inicializada instancia de WSO2AuthenticationServiceImpl con providerId="+providerId);
    }
    public WSO2AuthenticationServiceImpl(String providerId, PersonService personService, AuthorityService authorityService) {
        super();
        this.providerId = providerId;
        this.personService = personService!=null?personService:new PersonServiceImpl();
        this.authorityService = authorityService!=null?authorityService:new AuthorityServiceImpl();
        if(authorityService instanceof AuthorityServiceImpl){
            ((AuthorityServiceImpl)authorityService).setPersonService(personService);
            ((AuthorityServiceImpl)authorityService).setAuthenticationService(this);
            ((AuthorityServiceImpl)authorityService).setTenantService(new MultiTServiceImpl());
            ((AuthorityServiceImpl)authorityService).setPolicyComponent(new PolicyComponentImpl(new DictionaryComponent()));
            ((AuthorityServiceImpl)authorityService).setAuthorityDAO(new AuthorityDAOImpl());
            ((AuthorityServiceImpl)authorityService).setUserNameMatcher(new UserNameMatcherImpl());
            //((AuthorityServiceImpl)authorityService).setPermissionServiceSPI(new AllowPermissionServiceImpl());
            ((AuthorityServiceImpl)authorityService).init();
        }
        logger.info("Inicializada instancia de WSO2AuthenticationServiceImpl con providerId="+providerId+" y (personService!=null)=>"+(personService!=null)+" y (authorityService!=null)=>"+(personService!=null)+".");

    }
    // Métodos existentes (incluidos setters para personService y authorityService)
    public WSO2AuthenticationServiceImpl() {
        super();
        this.providerId = "wso2";
        personService=new PersonServiceImpl();
        authorityService=new AuthorityServiceImpl();
        if(authorityService instanceof AuthorityServiceImpl){
            ((AuthorityServiceImpl)authorityService).setPersonService(personService);
            ((AuthorityServiceImpl)authorityService).setAuthenticationService(this);
            ((AuthorityServiceImpl)authorityService).setTenantService(new MultiTServiceImpl());
            ((AuthorityServiceImpl)authorityService).setPolicyComponent(new PolicyComponentImpl(new DictionaryComponent()));
            ((AuthorityServiceImpl)authorityService).setAuthorityDAO(new AuthorityDAOImpl());
            ((AuthorityServiceImpl)authorityService).setUserNameMatcher(new UserNameMatcherImpl());
            AllowPermissionServiceImpl allowPermissionService = new AllowPermissionServiceImpl();
            ((AuthorityServiceImpl)authorityService).setPermissionServiceSPI(allowPermissionService);
            ((AuthorityServiceImpl)authorityService).init();
        }
        logger.info("Inicializada instancia de WSO2AuthenticationServiceImpl con providerId=wso2 por defecto.");
    }

    public OidcIdToken createOidcToken(RSAPublicKey publicKey,RSAPrivateKey privateKey,OAuth2AccessTokenResponse accessTokenResponse,String tokenKey) throws Exception {
        String jwtToken =(String)accessTokenResponse.getAdditionalParameters().get(tokenKey);
        JWT jwt = JWTParser.parse(jwtToken);

        if (verifyJwtSignature(jwtToken,publicKey)) {
            // JWT firmado
            SignedJWT signedJWT = (SignedJWT) jwt;
            JWSHeader header = signedJWT.getHeader();
            System.out.println("Algoritmo de firma: " + header.getAlgorithm());
            System.out.println("Tipo: " + header.getType());
        } else if (verifyJwtCypher(jwtToken,privateKey)) {
            // JWT cifrado
            EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
            JWEHeader header = encryptedJWT.getHeader();
            PayLoadEncryptedJWT payload = decryptJwt(jwtToken, privateKey);
            // Obtener las reclamaciones del JWT (esto será un conjunto de claves-valor que contiene los datos del token)
            JWTClaimsSet claimsSet = payload.getEncripted().getJWTClaimsSet();
            // Obtener las reclamaciones necesarias para OidcIdToken
            Date issuedAt = claimsSet.getIssueTime();
            Date expiresAt = claimsSet.getExpirationTime();
            Map<String, Object> claims = claimsSet.getClaims();
            System.out.println("Algoritmo de cifrado (clave): " + header.getAlgorithm());
            System.out.println("Algoritmo de cifrado (contenido): " + header.getEncryptionMethod());
            OidcIdToken idToken = new OidcIdToken(jwtToken,issuedAt.toInstant(), expiresAt.toInstant(), claims);
           return idToken;
        } else {
            System.out.println("Tipo de token no reconocido");
        }
       // OidcIdToken oidc=new OidcIdToken()
        return null;
    }
    public JWSHeader getJWSHeader(RSAPublicKey publicKey,RSAPrivateKey privateKey,OAuth2AccessTokenResponse accessTokenResponse,String tokenKey) throws Exception {
        String jwtToken =(String)accessTokenResponse.getAdditionalParameters().get(tokenKey);
        JWT jwt = JWTParser.parse(jwtToken);

        if (verifyJwtSignature(jwtToken,publicKey)) {
            // JWT firmado
            SignedJWT signedJWT = (SignedJWT) jwt;
            return signedJWT.getHeader();
        }
        return null;
    }
    public JWEHeader getJWEHeader(RSAPublicKey publicKey,RSAPrivateKey privateKey,OAuth2AccessTokenResponse accessTokenResponse,String tokenKey) throws Exception {
        String jwtToken =(String)accessTokenResponse.getAdditionalParameters().get(tokenKey);
        JWT jwt = JWTParser.parse(jwtToken);

        if (verifyJwtCypher(jwtToken,privateKey)) {
            // JWT cifrado
            EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
            return encryptedJWT.getHeader();
        }
        return null;
    }

    // Método para verificar la firma del JWT
    public static boolean verifyJwtSignature(String jwtToken, RSAPublicKey publicKey) throws Exception {
        // Decodificar el JWT
        JWT jwt = JWTParser.parse(jwtToken);

        if (jwt instanceof SignedJWT) {
            SignedJWT signedJWT = (SignedJWT) jwt;

            // Obtener el encabezado y el algoritmo de firma
            JWSHeader header = signedJWT.getHeader();
            JWSAlgorithm algorithm = header.getAlgorithm();
            System.out.println("Algoritmo de firma: " + algorithm);

            // Verificador de la firma con la clave pública
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            // Verificar la firma
            boolean isSignatureValid = signedJWT.verify(verifier);
            if (isSignatureValid) {
                System.out.println("Firma verificada correctamente.");
                return true;
            } else {
                System.out.println("Firma no válida.");
                return false;
            }
        } else {
            System.out.println("El JWT no es un JWT firmado.");
            return false;
        }
    }
    // Método para verificar y descifrar el JWT cifrado
    public PayLoadEncryptedJWT decryptJwt(String jwtToken, RSAPrivateKey privateKey) throws Exception {
        // Decodificar el JWT
        JWT jwt = JWTParser.parse(jwtToken);

        if (jwt instanceof EncryptedJWT) {
            EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;

            // Obtener el encabezado JWE (información sobre el algoritmo de cifrado)
            JWEHeader jweHeader = encryptedJWT.getHeader();
            JWEAlgorithm jweAlgorithm = jweHeader.getAlgorithm();
            EncryptionMethod encryptionMethod = jweHeader.getEncryptionMethod();

            System.out.println("Algoritmo de cifrado: " + jweAlgorithm);
            System.out.println("Método de cifrado: " + encryptionMethod);

            // Desencriptar el JWT utilizando la clave privada
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            encryptedJWT.decrypt(decrypter);
            // Una vez descifrado, obtén las reclamaciones
            JWTClaimsSet claimsSet = encryptedJWT.getJWTClaimsSet();
            // Obtener la carga útil decodificada
            String payload = encryptedJWT.getPayload().toString();
            return new PayLoadEncryptedJWT(payload,encryptedJWT);
        } else {
            System.out.println("El JWT no es un JWT cifrado.");
            return null;
        }
    }

    // Método auxiliar para construir el OidcIdToken
    private static OidcIdToken buildOidcIdToken(JWTClaimsSet claimsSet, String idToken) {
        Date issuedAt = claimsSet.getIssueTime();
        Date expiresAt = claimsSet.getExpirationTime();
        Map<String, Object> claims = claimsSet.getClaims();

        // Construir la instancia de OidcIdToken usando los valores extraídos
        return new OidcIdToken(idToken, issuedAt.toInstant(), expiresAt.toInstant(), claims);
    }
    // Método para verificar y descifrar el JWT cifrado, retorna true si el cifrado es válido
    public static boolean verifyJwtCypher(String jwtToken, RSAPrivateKey privateKey) {
        try {
            // Decodificar el JWT
            JWT jwt = JWTParser.parse(jwtToken);

            if (jwt instanceof EncryptedJWT) {
                EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;

                // Obtener el encabezado JWE (información sobre el algoritmo de cifrado)
                JWEHeader jweHeader = encryptedJWT.getHeader();
                JWEAlgorithm jweAlgorithm = jweHeader.getAlgorithm();
                EncryptionMethod encryptionMethod = jweHeader.getEncryptionMethod();

                System.out.println("Algoritmo de cifrado: " + jweAlgorithm);
                System.out.println("Método de cifrado: " + encryptionMethod);

                // Desencriptar el JWT utilizando la clave privada
                RSADecrypter decrypter = new RSADecrypter(privateKey);
                encryptedJWT.decrypt(decrypter);

                // Si llegamos aquí, significa que el cifrado fue válido
                return true;
            } else {
                System.out.println("El JWT no es un JWT cifrado.");
                return false;
            }
        } catch (Exception e) {
            System.out.println("Error durante el descifrado o no es un JWT cifrado: " + e.getMessage());
            return false;
        }
    }
    // Método para decodificar la carga del JWT (solo si la firma es válida)
    public static String decodeJwtPayload(String jwtToken, RSAPublicKey publicKey) throws Exception {
        if (verifyJwtSignature(jwtToken, publicKey)) {
            JWT jwt = JWTParser.parse(jwtToken);

            // Decodificar la carga (payload) del JWT
            String[] parts = jwtToken.split("\\.");
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            System.out.println("Carga decodificada: " + payload);
            return payload;
        } else {
            System.out.println("La firma no es válida, no se puede decodificar el payload.");
        }
        return null;
    }

    public HttpSession getSession() {
        return session;
    }

    public WSO2AuthenticationServiceImpl setSession(HttpSession session) {
        this.session = session;
        ServiceLocator.registerIntegrator(ServiceLocator.getIntegrator().setSession(session));
        return this;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public WSO2AuthenticationServiceImpl setRequest(HttpServletRequest request) {
        this.request = request;
        this.session=request.getSession();
        ServiceLocator.registerIntegrator(ServiceLocator.getIntegrator().setRequest(this.request).setSession(this.session));
        return this;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public WSO2AuthenticationServiceImpl setResponse(HttpServletResponse response) {
        this.response = response;
        ServiceLocator.registerIntegrator(ServiceLocator.getIntegrator().setResponse(response));
        return this;
    }

    public void setProviderId(String providerId){
        this.providerId=providerId;
    }

    public String getProviderId(){
        return this.providerId;
    }

    public Date getExpirationTimestamp(long expiresIn) {
        long currentTimeMillis = System.currentTimeMillis();
        long expirationMillis = currentTimeMillis + (expiresIn * 1000L);
        return new Date(expirationMillis);
    }
    public String getTicket(String accessToken,boolean autoCreate){

        boolean isValid = validateTokenWithWSO2(accessToken);
        logger.info("validateTokenWithWSO2:"+isValid);
        Wso2SecurityConfig wso2SecurityConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
        String ticketMode = wso2SecurityConfig.getPropertyByKey("oauth2.client.provider.wso2.ticket-mode","standar");
        logger.info("ticketMode="+ticketMode);
        logger.info("ticketMode='custom'"+(ticketMode=="custom"));
        logger.info("ticketMode='custom'"+"custom".equals(ticketMode));
        if(!"custom".equals(ticketMode)) {
            logger.info("Iniciando generación standar de Ticket::::::::::::::::::::::::::::::");
            ClientServiceIntegration ClientServiceIntegration= ServiceLocator.getIntegrator();
            ClientServiceIntegration.setSession(this.session);
            if(ClientServiceIntegration!=null){
                logger.info("Instancia de ClientServiceIntegration inicializada satisfactoriamente::::::::::::::::::::::::::::::");
                String username=getUsernameFromToken(accessToken);
                logger.info("Se obtiene el usuario:"+username+" desde el accessToken");
                try {
                    ClientServiceIntegration.initRequestContext(request,response,session);
                } catch (RequestContextException e) {
                    logger.severe("ERROR en initRequestContext:::::::::::::::::::::::::::::\n"+e.getMessage());
                }
                String alfTicket = ClientServiceIntegration.getTicket(session.getId(), username, accessToken);
                logger.info("Se obtiene el Ticket:"+alfTicket+" desde el accessToken");
                return alfTicket;
            }
        }

        String validDuration=wso2SecurityConfig.getPropertyByKey("oauth2.client.provider.wso2.ticket-validDuration","PT2H");
        logger.info("Ticket-ValidDuration:"+validDuration);
        if(isValid){
            String user=getUsernameFromToken(accessToken);
            TransactionalCache tcache=new TransactionalCache();
            tcache.setSharedCache(new DefaultSimpleCache<>());
            tcache.setDisableSharedCache(false);
            tcache.setName("UsernameToTicketIdCache");
            InMemoryTicketComponentImpl cmp=new InMemoryTicketComponentImpl();
            cmp.setUsernameToTicketIdCache(tcache);

            tcache=new TransactionalCache();
            tcache.setSharedCache(new DefaultSimpleCache<>());
            tcache.setDisableSharedCache(false);
            tcache.setName("TicketsCache");
            cmp.setTicketsCache(tcache);
            cmp.setValidDuration(validDuration);
            String ticket= cmp.getCurrentTicket(user,autoCreate);
            logger.info("Ticket generado:"+ticket);
            return ticket;
        }
        return null;
    }
    public String getTicket(String accessToken, boolean autoCreate, InMemoryTicketComponentImpl.ExpiryMode expiryMode){
        boolean isValid = validateTokenWithWSO2(accessToken);
        logger.info("validateTokenWithWSO2:"+isValid);
        Wso2SecurityConfig wso2SecurityConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
        String validDuration=wso2SecurityConfig.getPropertyByKey("oauth2.client.provider.wso2.ticket-validDuration","PT2H");
        logger.info("Ticket-ValidDuration:"+validDuration);
        if(isValid){
            String user=getUsernameFromToken(accessToken);
            TransactionalCache tcache=new TransactionalCache();
            tcache.setSharedCache(new DefaultSimpleCache<>());
            tcache.setDisableSharedCache(false);
            tcache.setName("UsernameToTicketIdCache");
            InMemoryTicketComponentImpl cmp=new InMemoryTicketComponentImpl();
            cmp.setUsernameToTicketIdCache(tcache);

            tcache=new TransactionalCache();
            tcache.setSharedCache(new DefaultSimpleCache<>());
            tcache.setDisableSharedCache(false);
            tcache.setName("TicketsCache");
            cmp.setTicketsCache(tcache);
            cmp.setValidDuration(validDuration);
            cmp.setExpiryMode(expiryMode.name());
            String ticket= cmp.getCurrentTicket(user,autoCreate);
            logger.info("Ticket generado with ExpiryMode:"+ticket);
            return ticket;
        }
        return null;
    }
    public Wso2SecurityConfig getWso2SecurityConfig() {
        return Wso2SecurityConfig.create().loadProperties();
    }

    public Wso2AuthenticatorClient getWso2AuthenticatorClient(Wso2SecurityConfig wso2SecConfig) {
        return Wso2AuthenticatorClient.create(wso2SecConfig.getGlobalPropertyFile());
    }

    public cu.entalla.service.AuthenticationService getAuthenticationService(Wso2AuthenticatorClient client) {
        return new cu.entalla.service.AuthenticationService(client);
    }

    public cu.entalla.service.AuthenticationService getAuthenticationService() {
        Wso2SecurityConfig wso2SecConfig = getWso2SecurityConfig();
        Wso2AuthenticatorClient client = getWso2AuthenticatorClient(wso2SecConfig);
        AuthenticationStore.getInstance().setWso2SecurityConfig(wso2SecConfig);
        return getAuthenticationService(client);
    }
    @Override
    public void authenticate(String username, char[] accessToken) throws AuthenticationException {
        // 1. Convertir el char[] a String
        String token = new String(accessToken);

        // 2. Validar el token con WSO2
        boolean isValid = validateTokenWithWSO2(token);
        logger.info("Token válido:"+isValid);
        if (!isValid) {
            throw new AuthenticationException("Invalid access token.");
        }

        // 3. Obtener el username desde el token para asegurarse de que coincide
        String tokenUsername = getUsernameFromToken(token);
        logger.info("Usuario del Token:"+tokenUsername);
        if (!username.equals(tokenUsername)) {
            logger.severe("Username does not match token claims: [tokenUsername="+tokenUsername +" and username="+username+"].");
            throw new AuthenticationException("Username does not match token claims: [tokenUsername="+tokenUsername +" and username="+username+"].");
        }

        // 4. Verificar si el usuario existe en Alfresco
        if (userExists(username)) {
            // Actualizar los datos del usuario en Alfresco
            logger.info("El usuario "+username+" existe en Alfresco y se procede a actualizarlo...");
            updateUser(username, getEmailFromToken(token), getPhoneFromToken(token), extractAdditionalPropertiesFromToken(token));
        } else {
            // Crear el usuario si no existe
            logger.info("El usuario "+username+" no existe en Alfresco y se procede a crearlo...");
            createUser(username, getEmailFromToken(token), getPhoneFromToken(token), extractAdditionalPropertiesFromToken(token));
        }

        // 5. Establecer al usuario como autenticado en Alfresco
        logger.info("Ejecutando AuthenticationUtil.setFullyAuthenticatedUser("+username+")");
        Authentication authentication = AuthenticationUtil.setFullyAuthenticatedUser(username);
        logger.info("Ejecutando AuthenticationUtil.setFullAuthentication("+authentication.toString()+")");
        AuthenticationUtil.setFullAuthentication(authentication);
        // 6. Establecer el encabezado de usuario para Share
        logger.info("Ejecutando AuthenticationUtil.setRunAsUser("+username+")");
        AuthenticationUtil.setRunAsUser(username);
    }
    public Map<String, Object> extractAdditionalPropertiesFromToken(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            // Extraer propiedades adicionales según tus necesidades
            Map<String, Object> additionalProperties = new HashMap<>();
            additionalProperties.put("firstName", claims.getStringClaim("given_name"));
            additionalProperties.put("lastName", claims.getStringClaim("family_name"));

            return additionalProperties;
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for additional properties", e);
        }
    }
    public String getUsernameFromToken(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("username");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token", e);
        }
    }
    public String getExpireInFromToken(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getDateClaim("exp").toString();
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token", e);
        }
    }
    public String getPhoneFromToken(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("phone");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for phone", e);
        }
    }
    public String getEmailFromToken(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return claims.getStringClaim("email");
        } catch (ParseException e) {
            throw new AuthenticationException("Error parsing access token for email", e);
        }
    }
    public void setAuthenticatedUserForShare(String username) {
        // Establecer el encabezado de usuario para Share
        logger.info("Ejecutando setAuthenticatedUserForShare("+username+")");
        Authentication authentication = AuthenticationUtil.setFullyAuthenticatedUser(username);
        AuthenticationUtil.setFullAuthentication(authentication);
        AuthenticationUtil.setRunAsUser(username);
    }

    private void updateUser(String username, String email, String phoneNumber, Map<String, Object> additionalProperties) {
        NodeRef userNode = personService.getPerson(username);
        // Actualizar las propiedades básicas
        Map<QName, Serializable> updatedProperties = new HashMap<>();
        updatedProperties.put(QName.createQName("{http://www.alfresco.org/model/content/1.0}email"), email);
        updatedProperties.put(QName.createQName("{http://www.alfresco.org/model/content/1.0}phoneNumber"), phoneNumber);

        // Actualizar propiedades adicionales
        if (additionalProperties != null) {
            additionalProperties.forEach((key, value) -> updatedProperties.put(
                    QName.createQName("{http://www.alfresco.org/model/content/1.0}" + key),
                    (Serializable) value
            ));
        }
        logger.info("Ejecutando updateUser("+username+","+email+","+phoneNumber+",additionalProperties)");
        // Aplicar los cambios
        personService.setPersonProperties(username, updatedProperties);
    }


    public void authenticateWithToken(String accessToken) throws AuthenticationException {
        logger.info("Ejecutando authenticateWithToken("+accessToken+")");
        boolean isValid = validateTokenWithWSO2(accessToken);
        logger.info("Ejecutando validateTokenWithWSO2:"+isValid);
        if (!isValid) {
            throw new AuthenticationException("Invalid access token.");
        }
        String userName=getUsernameFromToken(accessToken);
        logger.info("userName from accessToken:"+userName);
        Authentication authentication = AuthenticationUtil.setFullyAuthenticatedUser(userName);
        AuthenticationUtil.setFullAuthentication(authentication);
        AuthenticationUtil.setRunAsUser(userName);
    }

    private boolean validateTokenWithWSO2(String accessToken) {
        return getAuthenticationService().isValidToken(accessToken);
    }


    /**
     * Verifica si un usuario existe en Alfresco.
     */
    public boolean userExists(String username) {
        return personService.personExists(username);
    }

    /**
     * Crea un usuario en Alfresco con los atributos obligatorios y opcionales.
     */
    public NodeRef createUser(String username, String email, String phoneNumber, Map<String, Object> properties) {
        if (userExists(username)) {
            throw new AuthenticationException("User already exists: " + username);
        }
        logger.info("Ejecutando createUser("+username+","+email+","+phoneNumber+",properties)");
        // Construir propiedades de Alfresco
        Map<QName, Serializable> alfrescoProperties = new HashMap<>();
        alfrescoProperties.put(QName.createQName("{http://www.alfresco.org/model/content/1.0}username"), username);
        alfrescoProperties.put(QName.createQName("{http://www.alfresco.org/model/content/1.0}email"), email);
        alfrescoProperties.put(QName.createQName("{http://www.alfresco.org/model/content/1.0}phoneNumber"), phoneNumber);

        // Agregar propiedades adicionales
        if (properties != null) {
            properties.forEach((key, value) -> alfrescoProperties.put(
                    QName.createQName("{http://www.alfresco.org/model/content/1.0}" + key),
                    (Serializable) value
            ));
        }

        NodeRef personNode = personService.createPerson(alfrescoProperties);
        authorityService.addAuthority("GROUP_EVERYONE", username);
        logger.info("Usuario creado satisfactoriamente....");
        return personNode;
    }

    // Getters y setters para PersonService y AuthorityService
    public void setPersonService(PersonService personService) {
        this.personService = personService;
    }

    public void setAuthorityService(AuthorityService authorityService) {
        this.authorityService = authorityService;
    }

    @Override
    public boolean isAuthenticationMutable(String userName) {
        return this.mutableAuthenticationService.isAuthenticationMutable(userName);
    }

    @Override
    public boolean isAuthenticationCreationAllowed() {
        return this.mutableAuthenticationService.isAuthenticationCreationAllowed();
    }

    @Override
    public void createAuthentication(String userName, char[] password) throws AuthenticationException {
        this.mutableAuthenticationService.createAuthentication(userName,password);
    }

    @Override
    public void updateAuthentication(String userName, char[] oldPassword, char[] newPassword) throws AuthenticationException {
        this.mutableAuthenticationService.updateAuthentication(userName,oldPassword,newPassword);
    }

    @Override
    public void setAuthentication(String userName, char[] newPassword) throws AuthenticationException {
        this.mutableAuthenticationService.setAuthentication(userName,newPassword);
    }

    @Override
    public void deleteAuthentication(String userName) throws AuthenticationException {
        this.mutableAuthenticationService.deleteAuthentication(userName);
    }

    @Override
    public void setAuthenticationEnabled(String userName, boolean enabled) throws AuthenticationException {
        this.mutableAuthenticationService.setAuthenticationEnabled(userName,enabled);
    }

    @Data
    @AllArgsConstructor
    private class PayLoadEncryptedJWT {
            String payLoad;
            EncryptedJWT encripted;
    }
}
