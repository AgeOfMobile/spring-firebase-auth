package firebase.auth;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Created by tri on 11/19/16.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({FirebaseResourceServerConfig.class, SecurityAdvice.class})
public @interface EnableFirebaseSecurity {
}
