package cu.entalla.model;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtAlgorithmConfig {

    private JWSAlgorithm jwsAlgorithm;       // Algoritmo de firma
    private JWEAlgorithm jweAlgorithm;       // Algoritmo de cifrado
    private EncryptionMethod encryptionMethod; // Método de cifrado
}
