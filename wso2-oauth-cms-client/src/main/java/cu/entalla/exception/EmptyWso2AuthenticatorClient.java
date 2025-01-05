package cu.entalla.exception;

import cu.entalla.udi.EnTallaException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@AllArgsConstructor
@NoArgsConstructor
public class EmptyWso2AuthenticatorClient extends Exception implements EnTallaException {
    String message="No existe instancia de Wso2AuthenticatorClient.";
    @Override
    public String getEnTallaMessage() {
        return message;
    }
}
