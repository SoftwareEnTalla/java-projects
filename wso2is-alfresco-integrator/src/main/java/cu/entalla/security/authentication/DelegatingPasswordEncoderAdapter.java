package cu.entalla.security.authentication;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

public class DelegatingPasswordEncoderAdapter implements net.sf.acegisecurity.providers.encoding.PasswordEncoder,org.springframework.security.crypto.password.PasswordEncoder {

    private final PasswordEncoder delegatingPasswordEncoder;

    public DelegatingPasswordEncoderAdapter() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        // Aquí puedes agregar los encoders que necesites
        //encoders.put("bcrypt", new BCryptPasswordEncoder());
        // Se utiliza bcrypt como el encoder predeterminado
        this.delegatingPasswordEncoder = PasswordEncoderFactory.createDelegatingPasswordEncoder(encoders,"bcrypt");
       // this.delegatingPasswordEncoder = new DelegatingPasswordEncoder("bcrypt", encoders);
    }

    // Este es el método que retorna el PasswordEncoder delegado
    public PasswordEncoder getDelegatingPasswordEncoder() {
        return delegatingPasswordEncoder;
    }

    public net.sf.acegisecurity.providers.encoding.PasswordEncoder getPasswordEncoderAdapter() {
        return  this;
    }

    @Override
    public String encodePassword(String rawPass, Object salt) {
        return delegatingPasswordEncoder.encode(rawPass);
    }

    @Override
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        return delegatingPasswordEncoder.matches(rawPass, encPass);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return delegatingPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegatingPasswordEncoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return PasswordEncoder.super.upgradeEncoding(encodedPassword);
    }
}
