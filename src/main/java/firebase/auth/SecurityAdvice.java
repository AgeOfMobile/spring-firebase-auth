package firebase.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Created by tri on 11/19/16.
 */
@RestControllerAdvice
public class SecurityAdvice {
    @ModelAttribute
    public FirebaseUser currentUser() {
        Authentication originAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (originAuthentication == null) return null;
        if (!originAuthentication.isAuthenticated()) return null;
        if (!(originAuthentication instanceof OAuth2Authentication)) return null;

        OAuth2Authentication authentication = (OAuth2Authentication)originAuthentication;
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails)authentication.getDetails();
        if (!(details.getDecodedDetails() instanceof FirebaseUser)) return null;

        return (FirebaseUser) details.getDecodedDetails();
    }
}
