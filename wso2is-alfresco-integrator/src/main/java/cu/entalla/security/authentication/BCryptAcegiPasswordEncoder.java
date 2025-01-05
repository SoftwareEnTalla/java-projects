package cu.entalla.security.authentication;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptAcegiPasswordEncoder implements net.sf.acegisecurity.providers.encoding.PasswordEncoder {

    private final org.springframework.security.crypto.password.PasswordEncoder springPasswordEncoder;

    public BCryptAcegiPasswordEncoder() {
        this.springPasswordEncoder = new BCryptPasswordEncoder();
    }

    @Override
    public String encodePassword(String rawPass, Object salt) {
        // El salt puede ser ignorado si no es necesario para BCrypt
        return springPasswordEncoder.encode(rawPass);
    }

    @Override
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        // El salt también se ignora en la validación
        return springPasswordEncoder.matches(rawPass, encPass);
    }
}
