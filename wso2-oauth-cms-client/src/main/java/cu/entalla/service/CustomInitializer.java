package cu.entalla.service;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.store.AuthenticationStore;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;

import java.util.logging.Logger;

@Service
public class CustomInitializer {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    private static final Logger logger = Logger.getLogger(CustomInitializer.class.getName());

    @PostConstruct
    public void overrideDefaultConfig() {
        if (clientRegistrationRepository!=null && !(clientRegistrationRepository instanceof InMemoryClientRegistrationRepository) && clientRegistrationRepository.findByRegistrationId("wso2")==null) {
            Wso2SecurityConfig wso2SecurityConfig = AuthenticationStore.getInstance().getWso2SecurityConfig();
            wso2SecurityConfig=wso2SecurityConfig!=null?wso2SecurityConfig:Wso2SecurityConfig.create();
            // Modifica la configuración del bean existente si es necesario
            ClientRegistrationRepository clientRegistrationRepository1 = wso2SecurityConfig.clientRegistrationRepository();

            logger.info("Custom configuration applied to ClientRegistrationRepository");
        }
    }
}
