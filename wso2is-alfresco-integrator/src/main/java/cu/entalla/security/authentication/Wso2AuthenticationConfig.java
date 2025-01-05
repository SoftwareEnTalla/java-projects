package cu.entalla.security.authentication;

import cu.entalla.app.context.SpringContextHolder;
import cu.entalla.model.AutoConfigureNamespaceServiceMemoryImpl;
import net.sf.acegisecurity.AuthenticationManager;
import org.alfresco.repo.admin.SysAdminParamsImpl;
import org.alfresco.repo.cache.DefaultSimpleCache;
import org.alfresco.repo.cache.MemoryCache;
import org.alfresco.repo.cache.SimpleCache;
import org.alfresco.repo.dictionary.CompiledModelsCache;
import org.alfresco.repo.dictionary.DictionaryComponent;
import org.alfresco.repo.dictionary.DictionaryDAO;
import org.alfresco.repo.dictionary.DictionaryDAOImpl;
import org.alfresco.repo.domain.node.ibatis.NodeDAOImpl;
import org.alfresco.repo.domain.permissions.ADMAccessControlListDAO;
import org.alfresco.repo.domain.permissions.AclDAOImpl;
import org.alfresco.repo.domain.permissions.FixedAclUpdater;
import org.alfresco.repo.domain.qname.ibatis.QNameDAOImpl;
import org.alfresco.repo.node.db.DbNodeServiceImpl;
import org.alfresco.repo.policy.BehaviourFilterImpl;
import org.alfresco.repo.policy.PolicyComponentImpl;
import org.alfresco.repo.policy.TransactionBehaviourQueue;
import org.alfresco.repo.policy.TransactionInvocationHandlerFactory;
import org.alfresco.repo.security.authentication.*;
import org.alfresco.repo.security.authority.AuthorityBridgeDAOImpl;
import org.alfresco.repo.security.authority.AuthorityBridgeTableAsynchronouslyRefreshedCache;
import org.alfresco.repo.security.authority.AuthorityDAOImpl;
import org.alfresco.repo.security.authority.AuthorityServiceImpl;
import org.alfresco.repo.security.permissions.impl.AllowPermissionServiceImpl;
import org.alfresco.repo.security.permissions.impl.PermissionServiceImpl;
import org.alfresco.repo.security.person.PersonServiceImpl;
import org.alfresco.repo.security.person.UserNameMatcherImpl;
import org.alfresco.repo.security.sync.ChainingUserRegistrySynchronizer;
import org.alfresco.repo.service.ServiceDescriptorRegistry;
import org.alfresco.repo.tenant.MultiTAdminServiceImpl;
import org.alfresco.repo.tenant.MultiTServiceImpl;
import org.alfresco.repo.transaction.RetryingTransactionHelper;
import org.alfresco.repo.transaction.TransactionServiceImpl;
import org.alfresco.repo.version.Node2ServiceImpl;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.repository.ChildAssociationRef;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AccessStatus;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.NamespacePrefixResolver;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.util.DynamicallySizedThreadPoolExecutor;
import org.alfresco.util.Pair;
import org.alfresco.util.PolicyIgnoreUtil;
import org.alfresco.util.cache.DefaultAsynchronouslyRefreshedCacheRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.logging.Logger;


//@Configuration
//@Component
//@ImportResource("classpath:/alfresco/extension/subsystems/authentication/wso2-auth/custom/wso2-auth-subsystem-context.xml")
public class Wso2AuthenticationConfig  {

    private static final Logger logger = Logger.getLogger(WSO2AuthenticationServiceImpl.class.getName());
    // Variable estática para el Singleton
    private static Wso2AuthenticationConfig instance;
    // Variable para controlar si ya se ha inicializado
    private static boolean hasInit = false;
    // Variables inyectadas a través del constructor
    private InMemoryTicketComponentImpl ticketComponent;
    private PersonService personService;
    private AuthorityService authorityService;
    private NodeService nodeService;
    private ServiceRegistry serviceRegistry;
    private WSO2AuthenticationServiceImpl wso2AuthenticationService;
    private MutableAuthenticationServiceImpl authenticationService;
    private PasswordEncoder passwordEncoder;
    private DaoAuthenticationProvider daoAuthenticationProvider;
    private Wso2AuthenticationProvider wso2AuthenticationProvider;
    private  WSO2AuthenticationComponent authenticationComponent;
    private UserDetailsService wso2UserDetailsService;
    private UserDetailsPasswordService userDetailsPasswordService;


    private UserDetailsByNameServiceWrapper userDetailsService;

    MultiTServiceImpl mtenant = new MultiTServiceImpl();
    DictionaryDAOImpl dictionaryDAO = new DictionaryDAOImpl();

    DictionaryComponent dictionaryComponent = new DictionaryComponent();

    AuthorityDAOImpl daoImpl = new AuthorityDAOImpl();

    PolicyComponentImpl policy;


    DefaultSimpleCache<Serializable, AccessStatus> accessCache = new DefaultSimpleCache<>();
    DefaultSimpleCache<Serializable, Set<String>> readerCache = new DefaultSimpleCache<>();
    DefaultSimpleCache<Serializable, Set<String>> readersDeniedCache = new DefaultSimpleCache<>();
    SimpleCache<Pair<String, String>, NodeRef> authorityLookupCache = new DefaultSimpleCache<>();
    SimpleCache<String, Set<String>> userAuthorityCache = new DefaultSimpleCache<>();
    SimpleCache<Pair<String, String>, List<ChildAssociationRef>> zoneAuthorityCache = new DefaultSimpleCache<>();
    SimpleCache<NodeRef, Pair<Map<NodeRef, String>, List<NodeRef>>> childAuthorityCache = new DefaultSimpleCache<>();
    SimpleCache  protectedUsersCache=new DefaultSimpleCache<>();

    public Wso2AuthenticationConfig(){

    }
    // Constructor solo para inyección de dependencias
   // @Autowired
    public Wso2AuthenticationConfig(InMemoryTicketComponentImpl ticketComponent,
                                    PersonService personService,
                                    AuthorityService authorityService,
                                    NodeService nodeService,
                                    ServiceRegistry serviceRegistry,
                                    MutableAuthenticationService wso2AuthenticationService,
                                    MutableAuthenticationService authenticationService,
                                    PasswordEncoder passwordEncoder,
                                    DaoAuthenticationProvider daoAuthenticationProvider,
                                    Wso2AuthenticationProvider wso2AuthenticationProvider,
                                    WSO2AuthenticationComponent authenticationComponent,
                                    UserDetailsService wso2UserDetailsService,
                                    UserDetailsPasswordService userDetailsPasswordService,
                                    UserDetailsByNameServiceWrapper userDetailsService) {
        this.ticketComponent = ticketComponent;
        this.personService = personService;
        this.authorityService = authorityService;
        this.nodeService = nodeService;
        this.serviceRegistry = serviceRegistry;
        this.passwordEncoder = passwordEncoder;
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.wso2AuthenticationProvider = wso2AuthenticationProvider;
        this.wso2AuthenticationService = (WSO2AuthenticationServiceImpl) wso2AuthenticationService;
        this.authenticationService= (MutableAuthenticationServiceImpl) authenticationService;
        this.authenticationComponent = authenticationComponent;
        this.wso2UserDetailsService = wso2UserDetailsService;
        this.userDetailsPasswordService = userDetailsPasswordService;
        this.userDetailsService = userDetailsService;

        if (instance == null) {
            instance = this;
        }
    }
    // Método estático para obtener la instancia del Singleton
    public static synchronized Wso2AuthenticationConfig getInstanceOfWso2AuthenticationConfig() {
        return instance;
    }
    public void init() {

        if(!hasInit){
            // Lógica que estaba en el constructor



            dictionaryDAO.setTenantService(mtenant);

            BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>();
            RejectedExecutionHandler handler = new ThreadPoolExecutor.CallerRunsPolicy();

            DynamicallySizedThreadPoolExecutor executor = new DynamicallySizedThreadPoolExecutor(
                    10, 100, 60, TimeUnit.SECONDS, workQueue, handler);

            CompiledModelsCache compiledModelsCache = new CompiledModelsCache();
            compiledModelsCache.setTenantService(mtenant);
            compiledModelsCache.setDictionaryDAO(dictionaryDAO);
            compiledModelsCache.setThreadPoolExecutor(executor);

            DefaultAsynchronouslyRefreshedCacheRegistry defaultAsynchronouslyRefreshedCacheRegistry = new DefaultAsynchronouslyRefreshedCacheRegistry();
            compiledModelsCache.setRegistry(defaultAsynchronouslyRefreshedCacheRegistry);
            dictionaryDAO.setDictionaryRegistryCache(compiledModelsCache);


            policy = new PolicyComponentImpl(dictionaryComponent);
            policy.setTenantService(mtenant);

            AuthenticationContextImpl authenticationContext = new AuthenticationContextImpl();
            authenticationContext.setTenantService(mtenant);

            AclDAOImpl aclDAO = new AclDAOImpl();

            BehaviourFilterImpl behaviourFilter = new BehaviourFilterImpl();
            behaviourFilter.setTenantService(mtenant);

            MultiTAdminServiceImpl mAdminTenant = new MultiTAdminServiceImpl();
            mAdminTenant.setAuthenticationContext(authenticationContext);
            mAdminTenant.setApplicationContext(SpringContextHolder.getApplicationContext("/alfresco"));
            mAdminTenant.setTenantService(mtenant);
            mAdminTenant.setBehaviourFilter(behaviourFilter);
            DbNodeServiceImpl dbNodeService = new DbNodeServiceImpl();
            dbNodeService.setDictionaryService(dictionaryComponent);
            NodeDAOImpl nodeDAO = new NodeDAOImpl();
            nodeDAO.setDictionaryService(dictionaryComponent);
            nodeDAO.setAclDAO(aclDAO);
            nodeDAO.setQnameDAO(new QNameDAOImpl());

            dbNodeService.setNodeDAO(nodeDAO);

            PermissionServiceImpl permissionService = new PermissionServiceImpl();
            permissionService.setTenantService(mtenant);
            permissionService.setAuthorityService(authorityService);
            permissionService.setDictionaryService(dictionaryComponent);
            permissionService.setNodeService(nodeService);
            permissionService.setPolicyComponent(policy);
            permissionService.setAccessCache(accessCache);
            permissionService.setReadersCache(readerCache);
            permissionService.setReadersDeniedCache(readersDeniedCache);
            permissionService.setAnyDenyDenies(true);

            TransactionServiceImpl transactionService = new TransactionServiceImpl();
            transactionService.setAllowWrite(true);
            transactionService.setTransactionManager(new DataSourceTransactionManager());
            transactionService.setMaxRetries(5);
            transactionService.setMaxRetryWaitMs(10000);
            transactionService.setMinRetryWaitMs(5000);
            transactionService.setRetryWaitIncrementMs(100);

            aclDAO.setNodeDAO(nodeDAO);
            permissionService.setAclDAO(aclDAO);

            FixedAclUpdater fixedAclUpdater = new FixedAclUpdater();
            fixedAclUpdater.setApplicationContext(SpringContextHolder.getApplicationContext("/alfresco"));
            fixedAclUpdater.setNodeDAO(nodeDAO);
            fixedAclUpdater.setPolicyComponent(policy);
            fixedAclUpdater.setTransactionService(transactionService);
            fixedAclUpdater.setForceSharedACL(true);
            fixedAclUpdater.setAccessControlListDAO(new ADMAccessControlListDAO());
            fixedAclUpdater.setPolicyIgnoreUtil(new PolicyIgnoreUtil());
            permissionService.setFixedAclUpdater(fixedAclUpdater);

            dbNodeService.setPermissionService(permissionService);
            mAdminTenant.setNodeService(dbNodeService);


            daoImpl.setAuthorityLookupCache(authorityLookupCache);
            daoImpl.setChildAuthorityCache(childAuthorityCache);
            daoImpl.setUserAuthorityCache(userAuthorityCache);
            daoImpl.setZoneAuthorityCache(zoneAuthorityCache);

           /* AutoConfigureNamespaceServiceMemoryImpl autoConfigureNamespaceServiceMemory = new AutoConfigureNamespaceServiceMemoryImpl().clear().registerDefaultNamespaces();
            NamespacePrefixResolver namespacePrefixResolver = namespacePrefixResolver(dictionaryDAO, autoConfigureNamespaceServiceMemory);
            daoImpl.setNamespacePrefixResolver(namespacePrefixResolver);
            dictionaryComponent.setDictionaryDAO((DictionaryDAO) namespacePrefixResolver);*/

            TransactionBehaviourQueue transactionBehaviourQueue = new TransactionBehaviourQueue();
            TransactionInvocationHandlerFactory transactionInvocationHandlerFactory = new TransactionInvocationHandlerFactory(transactionBehaviourQueue);
            policy.setTransactionInvocationHandlerFactory(transactionInvocationHandlerFactory);

            behaviourFilter.setDictionaryService(dictionaryComponent);
            policy.setBehaviourFilter(behaviourFilter);
            policy.setTryLockTimeout(60000);

            AuthorityBridgeDAOImpl adaoBridge = new AuthorityBridgeDAOImpl();
            daoImpl.setTenantService(mtenant);
            adaoBridge.setTenantService(mtenant);
            daoImpl.setAuthorityBridgeDAO(adaoBridge);
            daoImpl.setPersonService(personService);
            daoImpl.setPolicyComponent(policy);

            AuthorityBridgeTableAsynchronouslyRefreshedCache authorityBridgeTableAsynchronouslyRefreshedCache = new AuthorityBridgeTableAsynchronouslyRefreshedCache();
            authorityBridgeTableAsynchronouslyRefreshedCache.setAuthorityBridgeDAO(adaoBridge);
            authorityBridgeTableAsynchronouslyRefreshedCache.setAuthorityDAO(daoImpl);
            authorityBridgeTableAsynchronouslyRefreshedCache.setTenantService(mtenant);
            authorityBridgeTableAsynchronouslyRefreshedCache.setRegistry(defaultAsynchronouslyRefreshedCacheRegistry);
            authorityBridgeTableAsynchronouslyRefreshedCache.setTenantAdminService(new MultiTAdminServiceImpl());
            authorityBridgeTableAsynchronouslyRefreshedCache.setRetryingTransactionHelper(new RetryingTransactionHelper());
            authorityBridgeTableAsynchronouslyRefreshedCache.setThreadPoolExecutor(executor);
            daoImpl.setAuthorityBridgeTableCache(authorityBridgeTableAsynchronouslyRefreshedCache);

            authenticationComponent.setAuthenticationDao(new RepositoryAuthenticationDao());
            authenticationComponent.setPersonService(personService);
            authenticationComponent.setCompositePasswordEncoder(new CompositePasswordEncoder());
            authenticationComponent.setAuthenticationContext(authenticationContext);
            authenticationComponent.setAllowGuestLogin(true);
            authenticationComponent.setDefaultAdministratorUserNameList("admin,pmorellpersi,softwarentalla,pmorellpersi@gmail.com,softwarentalla@gmail.com");
            authenticationComponent.setDefaultAdministratorUserNames(Set.of("admin,pmorellpersi,softwarentalla,pmorellpersi@gmail.com,softwarentalla@gmail.com".split(",")));
            authenticationComponent.setDefaultGuestUserNameList("admin,pmorellpersi,softwarentalla,pmorellpersi@gmail.com,softwarentalla@gmail.com");
            authenticationComponent.setNodeService(nodeService);
            authenticationComponent.setSystemUserAsCurrentUser(mtenant.getCurrentUserDomain());
            authenticationComponent.setTransactionService(transactionService);
            authenticationComponent.setAuthenticationManager((AuthenticationManager) new ProviderManager(wso2AuthenticationProvider, daoAuthenticationProvider));
            authenticationComponent.setUserRegistrySynchronizer(new ChainingUserRegistrySynchronizer());

            this.authenticationComponent = authenticationComponent;

            wso2AuthenticationService.setAuthenticationComponent(authenticationComponent);
            wso2AuthenticationService.setTicketComponent(ticketComponent);
            wso2AuthenticationService.setProtectedUsersCache(protectedUsersCache);
            SysAdminParamsImpl sap = new SysAdminParamsImpl();
            sap.setApplicationContext(SpringContextHolder.getApplicationContext("/alfresco"));
            wso2AuthenticationService.setSysAdminParams(sap);
            wso2AuthenticationService.setAllowsUserCreation(true);
            wso2AuthenticationService.setAllowsUserDeletion(true);
            wso2AuthenticationService.setAllowsUserPasswordChange(true);
            wso2AuthenticationService.setProtectionEnabled(true);
            wso2AuthenticationService.setProtectionLimit(3);
            wso2AuthenticationService.setProtectionPeriodSeconds(180);
            wso2AuthenticationService.getDefaultAdministratorUserNames();

            authenticationService.setAuthenticationComponent(authenticationComponent);
            authenticationService.setTicketComponent(ticketComponent);
            authenticationService.setProtectedUsersCache(new MemoryCache<>());

            sap.setApplicationContext(SpringContextHolder.getApplicationContext("/alfresco"));
            authenticationService.setSysAdminParams(sap);
            authenticationService.setAllowsUserCreation(true);
            authenticationService.setAllowsUserDeletion(true);
            authenticationService.setAllowsUserPasswordChange(true);
            authenticationService.setProtectionEnabled(true);
            authenticationService.setProtectionLimit(3);
            authenticationService.setProtectionPeriodSeconds(180);
            authenticationService.getDefaultAdministratorUserNames();

            if (authorityService instanceof AuthorityServiceImpl) {
                ((AuthorityServiceImpl) authorityService).setPersonService(personService);
                ((AuthorityServiceImpl) authorityService).setTenantService(mtenant);
                ((AuthorityServiceImpl) authorityService).setPolicyComponent(policy);
                ((AuthorityServiceImpl) authorityService).setAuthorityDAO(daoImpl);
                ((AuthorityServiceImpl) authorityService).setUserNameMatcher(new UserNameMatcherImpl());
                ((AuthorityServiceImpl) authorityService).setPermissionServiceSPI(new AllowPermissionServiceImpl());
                ((AuthorityServiceImpl) authorityService).init();
                ((AuthorityServiceImpl) authorityService).setAuthenticationService(wso2AuthenticationService);
            }
            wso2AuthenticationService.setAuthorityService(authorityService);
            this.wso2AuthenticationService = wso2AuthenticationService;
            hasInit=true;
        }
    }
    public Wso2AuthenticationConfig configureNameSpacePrefixResolver(){
        AutoConfigureNamespaceServiceMemoryImpl autoConfigureNamespaceServiceMemory = new AutoConfigureNamespaceServiceMemoryImpl();
        NamespacePrefixResolver namespacePrefixResolver = namespacePrefixResolver(dictionaryDAO, autoConfigureNamespaceServiceMemory);
        daoImpl.setNamespacePrefixResolver(namespacePrefixResolver);
        dictionaryComponent.setDictionaryDAO((DictionaryDAO) namespacePrefixResolver);
        return this;
    }
    public NamespacePrefixResolver namespacePrefixResolver(DictionaryDAOImpl namespaceResolver, NamespaceService namespaceService) {


        // Registrar dinámicamente todos los prefijos
        namespaceService.getPrefixes().forEach(prefix -> {
            try {
                String uri = namespaceService.getNamespaceURI(prefix);
                // Validar que el URI no esté vacío o nulo
                if (uri != null && !uri.isEmpty() && prefix != null && !prefix.isEmpty()) {
                    namespaceResolver.addPrefix(prefix, uri);
                    logger.info("Registered prefix: " + prefix + " -> URI: " + uri);
                } else {
                    logger.severe("Skipping invalid prefix: " + prefix + " and Uri="+uri);
                }
            } catch (Exception e) {
                logger.severe("Error registering prefix: " + prefix + ". " + e.getMessage());
            }
        });

        return namespaceResolver;
    }

    /*@Bean
    public AuthenticationManager authenticationManager() {
        if(authenticationManager==null)
             return authenticationManager= new ProviderManager(Arrays.asList(daoAuthenticationProvider(), wso2AuthenticationProvider()));
        return authenticationManager;
    }*/

    @Bean
    public UserDetailsPasswordService userDetailsPasswordService(){
        if(userDetailsPasswordService==null) {
            return userDetailsPasswordService = (user, newPassword) -> {
                UserDetails newUser = User.withUserDetails(user).password(newPassword).build();
                CustomUserDetailsPasswordService bean = SpringContextHolder.getBean(CustomUserDetailsPasswordService.class);
                if(bean!=null){
                    newUser=bean.updatePassword(user,newPassword);
                }
                logger.info("Se actualizó el password del usuario:" + user.getUsername());
                return newUser;
            };
        }
        return userDetailsPasswordService;
    }
    @Bean
    public PersonService personService() {
        if(personService==null) {
            PersonService person = (PersonService) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(PersonService.class.getName());
            person = person != null ? person : new PersonServiceImpl();
            logger.info("NodeService!=null=>" + (person != null));
            return personService = person;
        }
        return personService;
    }
    @Bean
    public AuthorityService authorityService() {
        if(authorityService==null) {
            AuthorityService service = (AuthorityService) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(AuthorityService.class.getName());
            service = service != null ? service : new AuthorityServiceImpl();
            logger.info("NodeService!=null=>" + (service != null));
            if(service instanceof AuthorityServiceImpl){
             ((AuthorityServiceImpl)service).setPersonService(personService);
            }
            return authorityService = service;
        }
        return authorityService;
    }
    @Bean
    public NodeService nodeService() {
        if(nodeService==null) {
            NodeService node = (NodeService) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(NodeService.class.getName());
            node = node != null ? node : new Node2ServiceImpl();
            logger.info("NodeService!=null=>" + (node != null));
            return nodeService = node;
        }
        return nodeService;
    }
    @Bean
    public ServiceRegistry serviceRegistry() {
        if(serviceRegistry==null) {
            // Aquí estamos obteniendo el ServiceRegistry directamente desde Alfresco
            ServiceRegistry registry = (ServiceRegistry) org.alfresco.util.ApplicationContextHelper.getApplicationContext().getBean(ServiceRegistry.class.getName());
            registry = registry != null ? registry : new ServiceDescriptorRegistry();
            logger.info("ServiceRegistry!=null=>" + (registry != null));
            return serviceRegistry = registry;
        }

        return serviceRegistry;
    }

    @Bean
    public WSO2AuthenticationServiceImpl wso2AuthenticationService() {
        // Aquí estamos obteniendo el ServiceRegistry directamente desde Alfresco
        if(wso2AuthenticationService ==null)
          return wso2AuthenticationService =new WSO2AuthenticationServiceImpl("wso2",personService,authorityService);
        return wso2AuthenticationService;
    }
    @Bean
    public MutableAuthenticationService authenticationService() {
        // Aquí estamos obteniendo el ServiceRegistry directamente desde Alfresco
        return authenticationService=authenticationService!=null?authenticationService: (MutableAuthenticationServiceImpl) wso2AuthenticationService.getMutableAuthenticationService();
    }

    @Bean
    public InMemoryTicketComponentImpl ticketComponent() {
        if(ticketComponent==null) {
            InMemoryTicketComponentImpl component = new InMemoryTicketComponentImpl();
            component.setValidDuration("PT2H");
            component.setExpiryMode(InMemoryTicketComponentImpl.ExpiryMode.AFTER_FIXED_TIME.name());
            component.setTicketsExpire(true);
            component.setUseSingleTicketPerUser(true);
            return ticketComponent = component;
        }
        return ticketComponent;
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        if(passwordEncoder==null)
             return  passwordEncoder=  new DelegatingPasswordEncoderAdapter().getDelegatingPasswordEncoder();//  PasswordEncoderFactory.createDelegatingPasswordEncoder(new HashMap<>());
        return passwordEncoder;
    }
    @Bean
    public org.springframework.security.authentication.dao.DaoAuthenticationProvider daoAuthenticationProvider(){
        if(daoAuthenticationProvider==null) {
            return daoAuthenticationProvider=new org.springframework.security.authentication.dao.DaoAuthenticationProvider(passwordEncoder);
        }
        return daoAuthenticationProvider;
    }
    @Bean
    public cu.entalla.security.authentication.Wso2AuthenticationProvider wso2AuthenticationProvider(){
        if(wso2AuthenticationProvider==null)
            return  wso2AuthenticationProvider=new Wso2AuthenticationProvider();
        return wso2AuthenticationProvider;
    }
    @Bean
    public WSO2AuthenticationComponent authenticationComponent(){
        if(authenticationComponent==null)
            return authenticationComponent=new WSO2AuthenticationComponent(wso2AuthenticationService);
        return authenticationComponent;
    }
    @Bean
    public UserDetailsService wso2UserDetailsService(){
        if(wso2UserDetailsService==null)
            return wso2UserDetailsService=new cu.entalla.security.authentication.Wso2UserDetailsService(wso2AuthenticationService);
        return wso2UserDetailsService;
    }

    @Bean
    public org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper userDetailsByNameServiceWrapper(){
        if(userDetailsService==null)
         return userDetailsService=new org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper(wso2UserDetailsService);
        return userDetailsService;
    }

    // Setters
    public void setAccessCache(DefaultSimpleCache<Serializable, AccessStatus> accessCache) {
        this.accessCache = accessCache;
    }

    public void setReaderCache(DefaultSimpleCache<Serializable, Set<String>> readerCache) {
        this.readerCache = readerCache;
    }

    public void setReadersDeniedCache(DefaultSimpleCache<Serializable, Set<String>> readersDeniedCache) {
        this.readersDeniedCache = readersDeniedCache;
    }

    public void setAuthorityLookupCache(SimpleCache<Pair<String, String>, NodeRef> authorityLookupCache) {
        this.authorityLookupCache = authorityLookupCache;
    }

    public void setUserAuthorityCache(SimpleCache<String, Set<String>> userAuthorityCache) {
        this.userAuthorityCache = userAuthorityCache;
    }

    public void setZoneAuthorityCache(SimpleCache<Pair<String, String>, List<ChildAssociationRef>> zoneAuthorityCache) {
        this.zoneAuthorityCache = zoneAuthorityCache;
    }

    public void setChildAuthorityCache(SimpleCache<NodeRef, Pair<Map<NodeRef, String>, List<NodeRef>>> childAuthorityCache) {
        this.childAuthorityCache = childAuthorityCache;
    }

    public void setProtectedUsersCache(SimpleCache protectedUsersCache) {
        this.protectedUsersCache = protectedUsersCache;
    }

    // Getters (opcional)
    public DefaultSimpleCache<Serializable, AccessStatus> getAccessCache() {
        return accessCache;
    }

    public DefaultSimpleCache<Serializable, Set<String>> getReaderCache() {
        return readerCache;
    }

    public DefaultSimpleCache<Serializable, Set<String>> getReadersDeniedCache() {
        return readersDeniedCache;
    }

    public SimpleCache<Pair<String, String>, NodeRef> getAuthorityLookupCache() {
        return authorityLookupCache;
    }

    public SimpleCache<String, Set<String>> getUserAuthorityCache() {
        return userAuthorityCache;
    }

    public SimpleCache<Pair<String, String>, List<ChildAssociationRef>> getZoneAuthorityCache() {
        return zoneAuthorityCache;
    }

    public SimpleCache<NodeRef, Pair<Map<NodeRef, String>, List<NodeRef>>> getChildAuthorityCache() {
        return childAuthorityCache;
    }

    public SimpleCache getProtectedUsersCache() {
        return protectedUsersCache;
    }


    @EventListener
    public void handleContextRefreshed(ContextRefreshedEvent event) {
        if (!hasInit) {
            init();
            hasInit = true;
        }
    }

}
