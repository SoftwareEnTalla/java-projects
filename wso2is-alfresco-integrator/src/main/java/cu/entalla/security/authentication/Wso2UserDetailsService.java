package cu.entalla.security.authentication;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.logging.Logger;

@Component
public class Wso2UserDetailsService implements UserDetailsService {

    WSO2AuthenticationServiceImpl wso2AuthenticationService;
    private static final Logger logger = Logger.getLogger(Wso2UserDetailsService.class.getName());

    public Wso2UserDetailsService(){
        wso2AuthenticationService=new WSO2AuthenticationServiceImpl("wso2");
    }
    public Wso2UserDetailsService(WSO2AuthenticationServiceImpl wso2AuthenticationService){
        this.wso2AuthenticationService=wso2AuthenticationService;
    }
    public void setWso2AuthenticationService(WSO2AuthenticationServiceImpl wso2AuthenticationService){
        this.wso2AuthenticationService=wso2AuthenticationService;
    }
    public WSO2AuthenticationServiceImpl getWso2AuthenticationService(){
        return this.wso2AuthenticationService;
    }
    @Override
    public UserDetails loadUserByUsername(String accessToken) throws UsernameNotFoundException {
        // Suponiendo que UserRepository extiende JpaRepository
        String userName=this.wso2AuthenticationService.getUsernameFromToken(accessToken);
        logger.info("Ejecutando loadUserByUsername for user:"+userName);
        if (userName == null) {
            logger.severe("User not found:"+userName);
            throw new UsernameNotFoundException("User not found: " + userName);
        }
        String ticket=this.wso2AuthenticationService.getTicket(accessToken,true);
        logger.severe("Ticket:"+ticket);
        return User.withUsername(userName)
                .password(ticket)
                .disabled(false)
                .roles("ROLE_AUTHENTICATED","ROLE_USER")
                .build();
    }
}