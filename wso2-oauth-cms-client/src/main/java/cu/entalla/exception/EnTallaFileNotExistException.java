package cu.entalla.exception;

import cu.entalla.udi.EnTallaException;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class EnTallaFileNotExistException extends Exception implements EnTallaException {
    String message;
    @Override
    public String getEnTallaMessage() {
        return message;
    }
}
