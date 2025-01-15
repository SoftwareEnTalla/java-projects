package cu.entalla.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.SecurityFilterChain;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


@Configuration
public class SecurityConfig {

    @Autowired
    Wso2SecurityConfig wso2SecurityConfig;

    @Bean
    public JwtDecoder jwtDecoderFromJwks() {
        // Cargar el JWKS desde la URL remota
        try {
            return wso2SecurityConfig.jwtDecoder();
        } catch (Exception e) {
            throw new RuntimeException("Error al configurar JWT Decoder desde JWKS URI", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoderFromPem() {
        // Cargar clave pública desde un archivo PEM
        try {
            return wso2SecurityConfig.jwtLocalDecoder();
        } catch (Exception e) {
            throw new RuntimeException("Error al cargar la clave pública desde PEM", e);
        }
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        String [] autorized=new String[]{"/wso2/oauth2/login", "/wso2/oauth2/callback","/wso2/oauth2/logout"};

        http.csrf().disable()  // Desactiva la protección CSRF
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(autorized).permitAll()  // Permite sin autenticación a ciertas URLs
                        .anyRequest().authenticated()  // Requiere autenticación para el resto de las URLs
                )
                .oauth2Login(Customizer.withDefaults())  // Configura el login con OAuth2 predeterminado
                .oauth2ResourceServer()  // Configura el manejo de recursos OAuth2
                .jwt()  // Configura el decodificador JWT
                .decoder(jwtDecoderFromPem());  // Usar el JwtDecoder desde el archivo PEM

        return http.build();
    }

}


