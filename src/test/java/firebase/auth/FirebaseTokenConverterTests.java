package firebase.auth;

import org.junit.Test;

/**
 * Created by tri on 11/20/16.
 */
public class FirebaseTokenConverterTests {
    @Test
    public void testDownloadKeys() {
        new FirebaseTokenConverter("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");
    }
}
