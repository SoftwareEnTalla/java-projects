package cu.entalla.store;

import cu.entalla.config.Wso2SecurityConfig;
import cu.entalla.model.OpenIDConfiguration;
import cu.entalla.model.TokenResponseModel;
import cu.entalla.model.UserProfile;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import javax.net.ssl.TrustManager;
import java.util.logging.Logger;

@Getter
@Setter
public class AuthenticationStore {

    private static AuthenticationStore _instance;
    private ClientRegistrationRepository clientRegistrationRepository;
    private Wso2SecurityConfig wso2SecurityConfig;
    private TrustManager trustManager;
    private OpenIDConfiguration openIdConfiguration;
    private TokenResponseModel tokenModel;
    private UserProfile userProfile;
    private static final Logger logger = Logger.getLogger(AuthenticationStore.class.getName());
    private AuthenticationStore(){

    }
    public static AuthenticationStore getInstance(){
       if(AuthenticationStore._instance==null)
       {
           AuthenticationStore._instance=new AuthenticationStore();
           AuthenticationStore._instance.wso2SecurityConfig= Wso2SecurityConfig.create();
       }
       return AuthenticationStore._instance;
    }
    public  boolean hasClientRegistrationRepository(){
        return clientRegistrationRepository!=null;
    }

    public void setWso2SecurityConfig(Wso2SecurityConfig wso2SecurityConfig){
         if(wso2SecurityConfig !=null && wso2SecurityConfig.getClientId()!=null)
          AuthenticationStore.getInstance().wso2SecurityConfig =this.wso2SecurityConfig = wso2SecurityConfig;
    }
    public Wso2SecurityConfig getWso2SecurityConfig(){
         return AuthenticationStore.getInstance().wso2SecurityConfig;
    }
    public void setOpenIdConfiguration(OpenIDConfiguration openIdConfiguration){
        AuthenticationStore.getInstance().openIdConfiguration=this.openIdConfiguration=openIdConfiguration;
    }

}
