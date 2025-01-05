package cu.entalla.security.authentication;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsPasswordService implements UserDetailsPasswordService {

   // @Autowired
    private final UserRepository userRepository; // Reemplaza con tu repositorio de usuarios

   /* public CustomUserDetailsPasswordService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }*/
    public CustomUserDetailsPasswordService() {
        this.userRepository = new UserRepositoryImpl();
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        // Aquí actualizas la contraseña en tu base de datos
        if (user instanceof CustomUserDetails) { // Reemplaza con tu clase de usuario personalizada
            CustomUserDetails customUser = (CustomUserDetails) user;
            customUser.setPassword(newPassword); // Actualiza la contraseña
            userRepository.save(customUser); // Guarda el usuario actualizado en la base de datos
            return customUser;
        }
        throw new IllegalArgumentException("UserDetails no es de tipo CustomUserDetails");
    }
}
