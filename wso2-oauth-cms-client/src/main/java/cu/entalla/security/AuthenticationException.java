package cu.entalla.security;

import java.text.ParseException;

public class AuthenticationException extends Throwable {
    public AuthenticationException(String errorParsingAccessToken, ParseException e) {
    }
}
