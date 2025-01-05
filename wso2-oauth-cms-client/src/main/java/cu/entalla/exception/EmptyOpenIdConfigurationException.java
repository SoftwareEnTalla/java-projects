package cu.entalla.exception;

import cu.entalla.udi.EnTallaException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class EmptyOpenIdConfigurationException extends Exception implements EnTallaException {
    String message="No existe instancia de OpenIdConfiguration.";
    @Override
    public String getEnTallaMessage() {
        return message;
    }
}
