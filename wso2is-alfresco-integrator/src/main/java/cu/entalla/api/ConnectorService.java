package cu.entalla.api;

import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.exception.CredentialVaultProviderException;
import org.springframework.extensions.surf.exception.WebScriptsPlatformException;
import org.springframework.extensions.surf.util.ReflectionHelper;
import org.springframework.extensions.webscripts.connector.*;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class ConnectorService extends org.springframework.extensions.webscripts.connector.ConnectorService{

    private static final String PREFIX_CONNECTOR_SESSION = "_alfwsf_consession_";
    private static final String PREFIX_VAULT_SESSION = "_alfwsf_vaults_";
    private static Log logger = LogFactory.getLog(org.springframework.extensions.webscripts.connector.ConnectorService.class);
    private ConfigService configService;
    private RemoteConfigElement remoteConfig;
    private ApplicationContext applicationContext;
    private ReadWriteLock configLock = new ReentrantReadWriteLock();
    public ConnectorService() {
        super();
    }

    @Override
    public RemoteConfigElement getRemoteConfig() {
        this.configLock.readLock().lock();

        try {
            if (this.remoteConfig == null) {
                this.configLock.readLock().unlock();
                this.configLock.writeLock().lock();

                try {
                    if (this.remoteConfig == null) {
                        logger.info(":::::::::::::::::::::::::::::::::::::::::::  this.getConfigService()==> "+this.getConfigService().getClass());
                        this.remoteConfig = (RemoteConfigElement)this.getConfigService().getConfig("Remote").getConfigElement("remote");
                        if (this.remoteConfig == null) {
                            throw new WebScriptsPlatformException("The 'Remote' configuration was not found.");
                        }
                    }
                } finally {
                    this.configLock.readLock().lock();
                    this.configLock.writeLock().unlock();
                }
            }
        } finally {
            this.configLock.readLock().unlock();
        }

        return this.remoteConfig;
    }

    public Connector getConnector(String endpointId) throws ConnectorServiceException {
        if (endpointId == null) {
            throw new IllegalArgumentException("EndpointId cannot be null.");
        } else {
            return this.getConnector(endpointId, (UserContext)null, (HttpSession)null);
        }
    }

    public Connector getConnector(String endpointId, HttpSession session) throws ConnectorServiceException {
        if (endpointId == null) {
            throw new IllegalArgumentException("EndpointId cannot be null.");
        } else {
            return this.getConnector(endpointId, (String)null, session);
        }
    }

    public Connector getConnector(String endpointId, String userId, HttpSession session) throws ConnectorServiceException {
        if (endpointId == null) {
            throw new IllegalArgumentException("EndpointId cannot be null.");
        } else if (session == null) {
            throw new IllegalArgumentException("HttpSession cannot be null.");
        } else {
            Credentials credentials = null;
            if (userId != null) {
                try {
                    CredentialVault vault = this.getCredentialVault(session, userId);
                    if (vault != null) {
                        credentials = vault.retrieve(endpointId);
                    }
                } catch (CredentialVaultProviderException var7) {
                    throw new ConnectorServiceException("Unable to acquire credential vault", var7);
                }
            }

            ConnectorSession connectorSession = this.getConnectorSession(session, endpointId);
            UserContext userContext = new UserContext(userId, credentials, connectorSession);
            return this.getConnector(endpointId, userContext, session);
        }
    }

    public Connector getConnector(String endpointId, UserContext userContext, HttpSession session) throws ConnectorServiceException {
        if (endpointId == null) {
            throw new IllegalArgumentException("EndpointId cannot be null.");
        } else {
            RemoteConfigElement.EndpointDescriptor endpointDescriptor = this.getRemoteConfig().getEndpointDescriptor(endpointId);
            if (endpointDescriptor == null) {
                throw new ConnectorServiceException("Unable to find endpoint definition for endpoint id: " + endpointId);
            } else {
                String connectorId = endpointDescriptor.getConnectorId();
                if (connectorId == null) {
                    throw new ConnectorServiceException("The connector id property on the endpoint definition '" + endpointId + "' was empty");
                } else {
                    RemoteConfigElement.ConnectorDescriptor connectorDescriptor = this.getRemoteConfig().getConnectorDescriptor(connectorId);
                    if (connectorDescriptor == null) {
                        throw new ConnectorServiceException("Unable to find connector definition for connector id: " + connectorId + " on endpoint id: " + endpointId);
                    } else {
                        String url = endpointDescriptor.getEndpointUrl();
                        Connector connector = this.buildConnector(connectorDescriptor, url);
                        if (connector == null) {
                            String var10002 = connectorDescriptor.getImplementationClass();
                            throw new ConnectorServiceException("Unable to construct Connector for class: " + var10002 + ", connector id: " + connectorId);
                        } else {
                            String authId = connectorDescriptor.getAuthenticatorId();
                            if (authId != null) {
                                RemoteConfigElement.AuthenticatorDescriptor authDescriptor = this.getRemoteConfig().getAuthenticatorDescriptor(authId);
                                if (authDescriptor == null) {
                                    throw new ConnectorServiceException("Unable to find authenticator definition for authenticator id: " + authId + " on connector id: " + connectorId);
                                }

                                String authClass = authDescriptor.getImplementationClass();
                                Authenticator authenticator = this.buildAuthenticator(authClass);
                                connector = new AuthenticatingConnector((Connector)connector, authenticator);
                            }

                            RemoteConfigElement.IdentityType identity = endpointDescriptor.getIdentity();
                            Object credentials;
                            switch (identity) {
                                case DECLARED:
                                    credentials = null;
                                    if (userContext != null && userContext.getCredentials() != null) {
                                        credentials = userContext.getCredentials();
                                    }

                                    if (credentials == null) {
                                        String username = endpointDescriptor.getUsername();
                                        String password = endpointDescriptor.getPassword();
                                        credentials = new CredentialsImpl(endpointId);
                                        ((Credentials)credentials).setProperty("cleartextUsername", username);
                                        ((Credentials)credentials).setProperty("cleartextPassword", password);
                                        if (session != null) {
                                            try {
                                                CredentialVault vault = this.getCredentialVault(session, username);
                                                if (vault != null) {
                                                    vault.store((Credentials)credentials);
                                                }
                                            } catch (CredentialVaultProviderException var15) {
                                                throw new ConnectorServiceException("Unable to acquire credential vault", var15);
                                            }
                                        }
                                    }

                                    ((Connector)connector).setCredentials((Credentials)credentials);
                                    break;
                                case USER:
                                    credentials = null;
                                    if (userContext != null) {
                                        if (userContext.getCredentials() != null) {
                                            credentials = userContext.getCredentials();
                                        } else if (endpointDescriptor.getExternalAuth() && userContext.getUserId() != null) {
                                            credentials = new CredentialsImpl(endpointId);
                                            ((Credentials)credentials).setProperty("cleartextUsername", userContext.getUserId());
                                        }
                                    }

                                    if (credentials != null) {
                                        ((Connector)connector).setCredentials((Credentials)credentials);
                                    } else if (logger.isDebugEnabled()) {
                                        if (userContext != null) {
                                            Log var10000 = logger;
                                            String var10001 = userContext.getUserId();
                                            var10000.debug("Unable to find credentials for user: " + var10001 + " and endpoint: " + endpointId);
                                        } else {
                                            logger.debug("Unable to find credentials for endpoint: " + endpointId);
                                        }
                                    }
                            }

                            ConnectorSession connectorSession = null;
                            if (userContext != null && userContext.getConnectorSession() != null) {
                                connectorSession = userContext.getConnectorSession();
                            }

                            if (connectorSession == null) {
                                connectorSession = new ConnectorSession(endpointId);
                            }

                            ((Connector)connector).setConnectorSession(connectorSession);
                            return (Connector)connector;
                        }
                    }
                }
            }
        }
    }
    private Connector buildConnector(RemoteConfigElement.ConnectorDescriptor descriptor, String url) {
        Class[] argTypes = new Class[]{descriptor.getClass(), url.getClass()};
        Object[] args = new Object[]{descriptor, url};
        Connector conn = (Connector) ReflectionHelper.newObject(descriptor.getImplementationClass(), argTypes, args);
        if (conn instanceof ApplicationContextAware) {
            ((ApplicationContextAware)conn).setApplicationContext(this.applicationContext);
        }

        return conn;
    }

    private Authenticator buildAuthenticator(String className) throws ConnectorServiceException {
        Authenticator auth = (Authenticator)ReflectionHelper.newObject(className);
        if (auth == null) {
            throw new ConnectorServiceException("Unable to instantiate Authenticator: " + className);
        } else {
            if (auth instanceof ApplicationContextAware) {
                ((ApplicationContextAware)auth).setApplicationContext(this.applicationContext);
            }

            return auth;
        }
    }

}
