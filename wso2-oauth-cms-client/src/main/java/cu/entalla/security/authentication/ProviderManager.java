package cu.entalla.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.*;

public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {
    private static final Log logger = LogFactory.getLog(org.springframework.security.authentication.ProviderManager.class);
    private AuthenticationEventPublisher eventPublisher;
    private List<AuthenticationProvider> providers;
    protected MessageSourceAccessor messages;
    private AuthenticationManager parent;
    private boolean eraseCredentialsAfterAuthentication;

    public ProviderManager() {
        this(new ArrayList<>(), (AuthenticationManager)null);
        logger.info("ProviderManager en constructor vacío...");
    }

    public ProviderManager(AuthenticationProvider... providers) {
        this(Arrays.asList(providers), (AuthenticationManager)null);
        logger.info("ProviderManager en constructor con arreglo de providers...");
    }

    public ProviderManager(List<AuthenticationProvider> providers) {
        this(providers, (AuthenticationManager)null);
        logger.info("ProviderManager en constructor con Lista de providers sin parent...");
    }

    public ProviderManager(List<AuthenticationProvider> providers, AuthenticationManager parent) {
        logger.info("ProviderManager en constructor con Lista de providers con parent "+parent!=null?"distinto de null...":"igual null...");
        this.eventPublisher = new cu.entalla.security.authentication.ProviderManager.NullEventPublisher();
        this.providers =providers==null? new ArrayList<>():providers;
        this.messages = SpringSecurityMessageSource.getAccessor();
        this.eraseCredentialsAfterAuthentication = true;
        Assert.notNull(providers, "providers list cannot be null");
        if(providers.isEmpty())
        {
            logger.info("Lista de proveedores vacía en ProviderManager: Se adiciona por defecto instancia de Wso2AuthenticationProvider");
            cu.entalla.security.authentication.Wso2AuthenticationProvider provider=new Wso2AuthenticationProvider();
            //Wso2SecurityConfig wso2SecurityConfig = Wso2SecurityConfig.create();
            //DaoAuthenticationProvider daoAuthenticationProvider = wso2SecurityConfig.daoAuthenticationProvider();
            providers.add(provider);
            logger.info("Lista de proveedores con instancia de Wso2AuthenticationProvider adicionada.");
            /*if(daoAuthenticationProvider!=null) {
                providers.add(daoAuthenticationProvider);
                logger.info("Lista de proveedores con instancia de DaoAuthenticationProvider también.");
            }*/
        }
        this.providers = providers;
        parent = parent!=null?parent:new org.springframework.security.authentication.ProviderManager(providers);
        this.parent = parent;
        this.checkState();
    }

    public void setProviders(List<AuthenticationProvider> providers){
        this.providers=providers==null? new ArrayList<>():providers;
        this.eventPublisher = new cu.entalla.security.authentication.ProviderManager.NullEventPublisher();
        //this.providers = Collections.emptyList();
        this.messages = SpringSecurityMessageSource.getAccessor();
        this.eraseCredentialsAfterAuthentication = true;
        Assert.notNull(this.providers, "providers list cannot be null");
        //this.providers = providers;
        //this.parent = parent;
        this.checkState();
    }

    public void setParent(AuthenticationManager parent){
        this.parent=parent;
    }
    public void afterPropertiesSet() {
        this.checkState();
    }

    private void checkState() {
        logger.info("this.parent != null="+(this.parent != null));
        logger.info("!this.providers.isEmpty()="+(this.providers!=null && !this.providers.isEmpty()));
        if(this.providers!=null)
            logger.info("!CollectionUtils.contains(this.providers.iterator(), (Object)null)="+(!CollectionUtils.contains(this.providers.iterator(), (Object)null)));
        Assert.isTrue(this.parent != null || this.providers!=null && !this.providers.isEmpty(), "A parent AuthenticationManager or a list of AuthenticationProviders is required");
        if(this.providers!=null)
            Assert.isTrue(!CollectionUtils.contains(this.providers.iterator(), (Object)null), "providers list cannot contain null values");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Class<? extends Authentication> toTest = authentication.getClass();
        AuthenticationException lastException = null;
        AuthenticationException parentException = null;
        Authentication result = null;
        Authentication parentResult = null;
        int currentPosition = 0;
        int size = this.providers.size();
        Iterator var9 = this.getProviders().iterator();

        while(var9.hasNext()) {
            AuthenticationProvider provider = (AuthenticationProvider)var9.next();
            if (provider.supports(toTest)) {
                if (logger.isTraceEnabled()) {
                    Log var10000 = logger;
                    String var10002 = provider.getClass().getSimpleName();
                    ++currentPosition;
                    var10000.trace(LogMessage.format("Authenticating request with %s (%d/%d)", var10002, currentPosition, size));
                }

                try {
                    result = provider.authenticate(authentication);
                    if (result != null) {
                        this.copyDetails(authentication, result);
                        break;
                    }
                } catch (InternalAuthenticationServiceException | AccountStatusException var14) {
                    this.prepareException(var14, authentication);
                    throw var14;
                } catch (AuthenticationException var15) {
                    lastException = var15;
                }
            }
        }

        if (result == null && this.parent != null) {
            try {
                parentResult = this.parent.authenticate(authentication);
                result = parentResult;
            } catch (ProviderNotFoundException var12) {
            } catch (AuthenticationException var13) {
                parentException = var13;
                lastException = var13;
            }
        }

        if (result != null) {
            if (this.eraseCredentialsAfterAuthentication && result instanceof CredentialsContainer) {
                ((CredentialsContainer)result).eraseCredentials();
            }

            if (parentResult == null) {
                this.eventPublisher.publishAuthenticationSuccess(result);
            }

            return result;
        } else {
            if (lastException == null) {
                lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotFound", new Object[]{toTest.getName()}, "No AuthenticationProvider found for {0}"));
            }

            if (parentException == null) {
                this.prepareException((AuthenticationException)lastException, authentication);
            }

            throw lastException;
        }
    }

    private void prepareException(AuthenticationException ex, Authentication auth) {
        this.eventPublisher.publishAuthenticationFailure(ex, auth);
    }

    private void copyDetails(Authentication source, Authentication dest) {
        if (dest instanceof AbstractAuthenticationToken token && dest.getDetails() == null) {
            token.setDetails(source.getDetails());
        }

    }

    public List<AuthenticationProvider> getProviders() {
        return this.providers;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setAuthenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
        Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
        this.eventPublisher = eventPublisher;
    }

    public void setEraseCredentialsAfterAuthentication(boolean eraseSecretData) {
        this.eraseCredentialsAfterAuthentication = eraseSecretData;
    }

    public boolean isEraseCredentialsAfterAuthentication() {
        return this.eraseCredentialsAfterAuthentication;
    }

    public static final class NullEventPublisher implements AuthenticationEventPublisher {
        private NullEventPublisher() {
        }

        public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        }

        public void publishAuthenticationSuccess(Authentication authentication) {
        }
    }
}