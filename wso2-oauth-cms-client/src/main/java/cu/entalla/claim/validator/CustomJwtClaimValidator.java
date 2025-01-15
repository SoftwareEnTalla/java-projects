package cu.entalla.claim.validator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.util.function.Predicate;

public class CustomJwtClaimValidator implements OAuth2TokenValidator<Jwt> {
    private final String claimName;
    private final Predicate<Object> predicate;

    public CustomJwtClaimValidator(String claimName, Predicate<Object> predicate) {
        this.claimName = claimName;
        this.predicate = predicate;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Object claimValue = jwt.getClaims().get(claimName);
        if (claimValue == null || !predicate.test(claimValue)) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_claim", "Invalid claim " + claimName, null));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
