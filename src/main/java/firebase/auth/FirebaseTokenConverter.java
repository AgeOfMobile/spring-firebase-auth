package firebase.auth;

import org.springframework.security.jwt.BinaryFormat;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.security.jwt.codec.Codecs.b64UrlDecode;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;

/**
 * Created by tri on 11/13/16.
 */
public class FirebaseTokenConverter extends JwtAccessTokenConverter {
    private final Map<String, SignatureVerifier> verifiers = new HashMap<>();
    private final JsonParser objectMapper = JsonParserFactory.create();

    public FirebaseTokenConverter(String jwksUri) {
        downloadKeys(jwksUri);
    }

    private void downloadKeys(String jwksUri) {
        verifiers.clear();

        RestTemplate restTemplate = new RestTemplate();
        Map response = restTemplate.getForObject(jwksUri, Map.class);

        for (Object key : response.keySet()) {
            String certificateString = (String)response.get(key);
            InputStream is = new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8));
            try {
                CertificateFactory f = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate)f.generateCertificate(is);
                PublicKey pk = certificate.getPublicKey();
                RsaVerifier verifier = new RsaVerifier((RSAPublicKey)pk);
                verifiers.put((String)key, verifier);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // TODO: refresh keys using the value of max-age in the Cache-Control header of the response
        // String cacheControl = response.getHeaders().getCacheControl();
    }

    @Override
    protected Map<String, Object> decode(String token) {
        try {
            // decode header to get 'alg' and 'kid'
            int firstPeriod = token.indexOf('.');
            if (firstPeriod <= 0) {
                throw new IllegalArgumentException("JWT must have header");
            }
            CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
            JwtHeader header = JwtHeaderHelper.create(buffer.toString());
            String kid = header.parameters.map.get("kid");
            SignatureVerifier verifier = verifiers.get(kid);

            // now decode
            Jwt jwt = JwtHelper.decodeAndVerify(token, verifier);
            String content = jwt.getClaims();
            Map<String, Object> map = objectMapper.parseMap(content);
            if (map.containsKey(EXP) && map.get(EXP) instanceof Integer) {
                Integer intValue = (Integer) map.get(EXP);
                map.put(EXP, new Long(intValue));
            }
            return map;
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new InvalidTokenException("Cannot convert access token to JSON", e);
        }
    }

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        OAuth2Authentication authentication = super.extractAuthentication(map);
        FirebaseUser user = new FirebaseUser(
                (String)map.get("user_id"),
                (String)map.get("email"),
                (String)map.get("name"),
                (String)map.get("picture")
        );
        authentication.setDetails(user);
        return authentication;
    }
}

class JwtHeaderHelper {

    static JwtHeader create(String header) {
        byte[] bytes = b64UrlDecode(header);
        return new JwtHeader(bytes, parseParams(bytes));
    }

    private static HeaderParameters parseParams(byte[] header) {
        Map<String, String> map = parseMap(utf8Decode(header));
        return new HeaderParameters(map);
    }

    private static Map<String, String> parseMap(String json) {
        if (json != null) {
            json = json.trim();
            if (json.startsWith("{")) {
                return parseMapInternal(json);
            }
            else if (json.equals("")) {
                return new LinkedHashMap<>();
            }
        }
        throw new IllegalArgumentException("Invalid JSON (null)");
    }

    private static Map<String, String> parseMapInternal(String json) {
        Map<String, String> map = new LinkedHashMap<>();
        json = trimLeadingCharacter(trimTrailingCharacter(json, '}'), '{');
        for (String pair : json.split(",")) {
            String[] values = pair.split(":");
            String key = strip(values[0], '"');
            String value = null;
            if (values.length > 0) {
                value = strip(values[1], '"');
            }
            if (map.containsKey(key)) {
                throw new IllegalArgumentException("Duplicate '" + key + "' field");
            }
            map.put(key, value);
        }
        return map;
    }

    private static String strip(String string, char c) {
        return trimLeadingCharacter(trimTrailingCharacter(string.trim(), c), c);
    }

    private static String trimTrailingCharacter(String string, char c) {
        if (string.length() >= 0 && string.charAt(string.length() - 1) == c) {
            return string.substring(0, string.length() - 1);
        }
        return string;
    }

    private static String trimLeadingCharacter(String string, char c) {
        if (string.length() >= 0 && string.charAt(0) == c) {
            return string.substring(1);
        }
        return string;
    }
}

class JwtHeader implements BinaryFormat {
    private final byte[] bytes;

    final HeaderParameters parameters;

    /**
     * @param bytes the decoded header
     * @param parameters the parameter values contained in the header
     */
    JwtHeader(byte[] bytes, HeaderParameters parameters) {
        this.bytes = bytes;
        this.parameters = parameters;
    }

    @Override
    public byte[] bytes() {
        return bytes;
    }

    @Override
    public String toString() {
        return utf8Decode(bytes);
    }
}

class HeaderParameters {
    final String alg;
    final Map<String, String> map;

    HeaderParameters(Map<String, String> map) {
        String alg = map.get("alg"), typ = map.get("typ");
        if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
            throw new IllegalArgumentException("typ is not \"JWT\"");
        }
        map.remove("alg");
        map.remove("typ");
        this.map = map;
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }
        this.alg = alg;
    }
}

