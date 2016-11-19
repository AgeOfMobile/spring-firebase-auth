package firebase.auth;

/**
 * Created by tri on 11/19/16.
 */
public class FirebaseUser {
    private String id;
    private String email;
    private String name;
    private String picture;

    public FirebaseUser(String id, String email, String name, String picture) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.picture = picture;
    }

    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public String getPicture() {
        return picture;
    }
}
