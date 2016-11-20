This small library helps you integrating [Firebase Auth](https://firebase.google.com/docs/auth/) into your Spring Boot application. It will parse ID Token (JWT) 
from the **Authorization** header, verify it then provides a **FirebaseUser** instance for the current request.

To use it, you need to add following snippet into your build.gradle file:

```gradle
repositories {
...
	maven {
		url 'https://dl.bintray.com/ageofmobile/spring-firebase-auth'
	}
...	
}

dependencies {
...
	compile('com.ageofmobile:spring-firebase-auth:0.0.2')
...
}
```

Add **@EnableFirebaseSecurity** to your Spring Boot Application class:

```java
@SpringBootApplication
@EnableResourceServer
@EnableFirebaseSecurity
public class Application {
	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}
```

Create a configuration class, extend from **FirebaseResourceServerConfig** class to configure your authentication/authorization rules:

```java
@Configuration
public class ResourceServerConfig extends FirebaseResourceServerConfig {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
    }
}
```

In your **resourses/application.yaml** (or **application.properties**) you need to add following configuration:

```
security.oauth2.resource.id: 'your-firebase-app-id'
```

In your controller classes, you can get the current user by adding a FirebaseUser parameter to request methods:

```java
@RestController
public class ContentControler {
    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public @ResponseBody String sayHello(FirebaseUser user) {
        return "Hello " + user.getName();
    }
}
```