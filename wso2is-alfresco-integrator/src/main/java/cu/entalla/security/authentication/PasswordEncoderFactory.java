package cu.entalla.security.authentication;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class PasswordEncoderFactory {

    public static PasswordEncoder createDelegatingPasswordEncoder(Map<String, PasswordEncoder> encoders,String defaultEncoder) {
        // Crear un mapa de PasswordEncoders
        Map<String, PasswordEncoder> innerEncoders = new HashMap<>();
        if(encoders!=null)
            innerEncoders.putAll(encoders);
        // Agregar todos los encoders disponibles

        innerEncoders.put("bcrypt", new BCryptPasswordEncoder());
        innerEncoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        innerEncoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        innerEncoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
        innerEncoders.put("noop", NoOpPasswordEncoder.getInstance()); // No seguro, solo para pruebas

        // Establecer uno predeterminado (por ejemplo, bcrypt)
        defaultEncoder = defaultEncoder==null?"noop":defaultEncoder;
        // Crear el DelegatingPasswordEncoder
        return new DelegatingPasswordEncoder(defaultEncoder, innerEncoders);
    }
}
