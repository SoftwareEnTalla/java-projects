package cu.entalla.security.authentication;

import org.alfresco.repo.security.person.PersonServiceImpl;
import org.alfresco.service.cmr.security.PersonService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.logging.Logger;

@Component
public class PersonServiceUserDetailsService implements UserDetailsService {


    private PersonService personService;
    private static final Logger logger = Logger.getLogger(PersonServiceUserDetailsService.class.getName());


    public PersonServiceUserDetailsService(PersonService personService) {
        this.personService = personService;
    }

    public PersonServiceUserDetailsService() {
        this.personService=new PersonServiceImpl();
    }

    @Override
    public UserDetails loadUserByUsername(String accessToken) throws UsernameNotFoundException {
        // Suponiendo que UserRepository extiende JpaRepository
        WSO2AuthenticationServiceImpl service=new WSO2AuthenticationServiceImpl();
        String userName=service.getUsernameFromToken(accessToken);
        logger.info("Ejecutando loadUserByUsername for user:"+userName);
        if (userName == null) {
            logger.severe("User not found:"+userName);
            throw new UsernameNotFoundException("User not found: " + userName);
        }
        String ticket=service.getTicket(accessToken,true);
        logger.severe("Ticket:"+ticket);
        return User.withUsername(userName)
                .password(ticket)
                .disabled(false)
                .roles("ROLE_AUTHENTICATED","ROLE_USER")
                .build();
    }
}
