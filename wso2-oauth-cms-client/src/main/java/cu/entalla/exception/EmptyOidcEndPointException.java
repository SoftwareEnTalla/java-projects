package cu.entalla.exception;

import cu.entalla.udi.EnTallaException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class EmptyOidcEndPointException extends Exception implements EnTallaException {
    String message="No existen EndPoint de OIDC disponibles.";
    @Override
    public String getEnTallaMessage() {
        return message;
    }
}
