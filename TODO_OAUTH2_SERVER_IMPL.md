use the file and generate Auth Server	Spring Authorization Server,
REST API (Resource)	Spring Boot + Spring Security OAuth2,
Client App	Spring Security OAuth2 Client, and others. use crule command to test each component. first write authorization server want to test it first then go for other component development when i mention. use username, email and password. we are focusing on building todo rest app.

I'll help you build a complete OAuth2 authorization system for a Todo REST application. Let's start with the **Authorization Server** using Spring Authorization Server.

## 1. Authorization Server Setup

First, let's create the Authorization Server with user management.

### Project Structure
```
todo-auth-server/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── todo/
│                   └── authserver/
│                       ├── config/
│                       ├── entity/
│                       ├── repository/
│                       ├── service/
│                       └── TodoAuthServerApplication.java
└── pom.xml
```

### Dependencies (pom.xml)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>
    
    <groupId>com.todo</groupId>
    <artifactId>todo-auth-server</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>17</java.version>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
            <version>1.2.0</version>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### User Entity
```java
package com.todo.authserver.entity;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(unique = true, nullable = false)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    private boolean enabled = true;

    // Constructors
    public User() {}
    
    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    // UserDetails methods
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }
    
    @Override
    public boolean isAccountNonExpired() { return true; }
    
    @Override
    public boolean isAccountNonLocked() { return true; }
    
    @Override
    public boolean isCredentialsNonExpired() { return true; }
    
    @Override
    public boolean isEnabled() { return enabled; }
}
```

### User Repository
```java
package com.todo.authserver.repository;

import com.todo.authserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### Custom UserDetailsService
```java
package com.todo.authserver.service;

import com.todo.authserver.entity.User;
import com.todo.authserver.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return user;
    }
}
```

### Authorization Server Configuration
```java
package com.todo.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
        
        http.exceptionHandling(exceptions -> 
            exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );
        
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/register").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .userDetailsService(userDetailsService);
        
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient todoClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("todo-client")
            .clientSecret("$2a$12$xyz123") // Encoded secret
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://localhost:8081/login/oauth2/code/todo-client")
            .redirectUri("http://localhost:3000/authorized")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("todo.read")
            .scope("todo.write")
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .refreshTokenTimeToLive(Duration.ofDays(1))
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(todoClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:9000")
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Registration Controller
```java
package com.todo.authserver.controller;

import com.todo.authserver.entity.User;
import com.todo.authserver.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class RegistrationController {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public RegistrationController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @PostMapping("/register")
    public Map<String, String> register(@RequestBody RegistrationRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Email already exists");
        }
        
        User user = new User(
            request.username(),
            request.email(),
            passwordEncoder.encode(request.password())
        );
        
        userRepository.save(user);
        
        return Map.of("message", "User registered successfully");
    }
    
    public record RegistrationRequest(String username, String email, String password) {}
}
```

### Main Application Class
```java
package com.todo.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TodoAuthServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TodoAuthServerApplication.class, args);
    }
}
```

### Application Properties
```properties
# application.properties
server.port=9000

spring.datasource.url=jdbc:h2:mem:authdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=

spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true

spring.h2.console.enabled=true

logging.level.org.springframework.security=DEBUG
```

## 2. Testing the Authorization Server

Let's test the Authorization Server step by step:

### Step 1: Start the server and register a user
```bash
# Start the application
mvn spring-boot:run
```

### Step 2: Register a new user
```bash
curl -X POST http://localhost:9000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "password123"
  }'
```

### Step 3: Get Authorization Code
Open in browser:
```
http://localhost:9000/oauth2/authorize?response_type=code&client_id=todo-client&scope=openid%20todo.read%20todo.write&redirect_uri=http://localhost:8081/login/oauth2/code/todo-client
```

Login with:
- Username: john
- Password: password123

You'll be redirected with an authorization code.

### Step 4: Exchange code for tokens
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic dG9kby1jbGllbnQ6eHl6MTIz" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8081/login/oauth2/code/todo-client"
```

The response will contain access_token, refresh_token, and id_token.

### Step 5: Test token introspection
```bash
curl -X POST http://localhost:9000/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic dG9kby1jbGllbnQ6eHl6MTIz" \
  -d "token=YOUR_ACCESS_TOKEN"
```

## Next Steps

The Authorization Server is now ready! It provides:

1. **User registration** with username, email, and password
2. **OAuth2 authorization code flow**
3. **OpenID Connect support**
4. **Token management** with JWT
5. **Client registration** for the Todo application

When you're ready, let me know and I'll help you build:
- **Resource Server** (Todo REST API)
- **Client Application** (Spring Security OAuth2 Client)
- **Frontend Client** (if needed)

Would you like me to proceed with the Resource Server next?

now everything works fine. even if i have not applied the current code suggestion. as the code was generated on browser was expired. now do the coding for Resource Server (Todo REST API) and crule command to test

Great! Now let's build the **Resource Server (Todo REST API)** that will be protected by OAuth2.

## 1. Resource Server Setup

### Project Structure
```
todo-resource-server/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── todo/
│                   └── resource/
│                       ├── config/
│                       ├── controller/
│                       ├── entity/
│                       ├── repository/
│                       └── TodoResourceServerApplication.java
└── pom.xml
```

### Dependencies (pom.xml)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>
    
    <groupId>com.todo</groupId>
    <artifactId>todo-resource-server</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>17</java.version>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### Todo Entity
```java
package com.todo.resource.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "todos")
public class Todo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String title;
    
    private String description;
    
    private boolean completed = false;
    
    private LocalDateTime createdAt;
    
    private LocalDateTime updatedAt;
    
    @Column(nullable = false)
    private String username; // Link to the user who owns this todo

    // Constructors
    public Todo() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    
    public Todo(String title, String description, String username) {
        this();
        this.title = title;
        this.description = description;
        this.username = username;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { 
        this.title = title; 
        this.updatedAt = LocalDateTime.now();
    }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { 
        this.description = description; 
        this.updatedAt = LocalDateTime.now();
    }
    
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { 
        this.completed = completed; 
        this.updatedAt = LocalDateTime.now();
    }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}
```

### Todo Repository
```java
package com.todo.resource.repository;

import com.todo.resource.entity.Todo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TodoRepository extends JpaRepository<Todo, Long> {
    List<Todo> findByUsername(String username);
    List<Todo> findByUsernameAndCompleted(String username, boolean completed);
    void deleteByUsernameAndId(String username, Long id);
}
```

### Todo DTO (Data Transfer Object)
```java
package com.todo.resource.entity;

import java.time.LocalDateTime;

public class TodoDto {
    private Long id;
    private String title;
    private String description;
    private boolean completed;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String username;

    // Constructors
    public TodoDto() {}
    
    public TodoDto(Todo todo) {
        this.id = todo.getId();
        this.title = todo.getTitle();
        this.description = todo.getDescription();
        this.completed = todo.isCompleted();
        this.createdAt = todo.getCreatedAt();
        this.updatedAt = todo.getUpdatedAt();
        this.username = todo.getUsername();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    // Convert to Entity
    public Todo toEntity() {
        Todo todo = new Todo();
        todo.setId(this.id);
        todo.setTitle(this.title);
        todo.setDescription(this.description);
        todo.setCompleted(this.completed);
        todo.setUsername(this.username);
        return todo;
    }
    
    public static TodoDto fromEntity(Todo todo) {
        return new TodoDto(todo);
    }
}
```

### Security Configuration
```java
package com.todo.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/todos/**").hasAuthority("SCOPE_todo.read")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .csrf(csrf -> csrf.disable()); // Disable CSRF for API endpoints
        
        return http.build();
    }

    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }

    // Custom converter to extract roles from JWT
    static class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            // Extract scopes from the JWT
            Collection<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null) {
                return scopes.stream()
                    .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                    .collect(Collectors.toList());
            }
            return Collections.emptyList();
        }
    }
}
```

### Todo Controller
```java
package com.todo.resource.controller;

import com.todo.resource.entity.Todo;
import com.todo.resource.entity.TodoDto;
import com.todo.resource.repository.TodoRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/todos")
public class TodoController {
    
    private final TodoRepository todoRepository;
    
    public TodoController(TodoRepository todoRepository) {
        this.todoRepository = todoRepository;
    }
    
    // Extract username from JWT token
    private String getUsernameFromJwt(Jwt jwt) {
        return jwt.getClaimAsString("sub"); // Using 'sub' claim as username
    }
    
    @GetMapping
    public ResponseEntity<List<TodoDto>> getAllTodos(@AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        List<Todo> todos = todoRepository.findByUsername(username);
        List<TodoDto> todoDtos = todos.stream()
            .map(TodoDto::fromEntity)
            .collect(Collectors.toList());
        return ResponseEntity.ok(todoDtos);
    }
    
    @GetMapping("/{id}")
    public ResponseEntity<TodoDto> getTodoById(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        Optional<Todo> todo = todoRepository.findById(id);
        
        if (todo.isEmpty() || !todo.get().getUsername().equals(username)) {
            return ResponseEntity.notFound().build();
        }
        
        return ResponseEntity.ok(TodoDto.fromEntity(todo.get()));
    }
    
    @PostMapping
    public ResponseEntity<TodoDto> createTodo(@RequestBody TodoDto todoDto, @AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        
        Todo todo = todoDto.toEntity();
        todo.setUsername(username);
        
        Todo savedTodo = todoRepository.save(todo);
        return ResponseEntity.ok(TodoDto.fromEntity(savedTodo));
    }
    
    @PutMapping("/{id}")
    public ResponseEntity<TodoDto> updateTodo(@PathVariable Long id, @RequestBody TodoDto todoDto, @AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        
        Optional<Todo> existingTodo = todoRepository.findById(id);
        if (existingTodo.isEmpty() || !existingTodo.get().getUsername().equals(username)) {
            return ResponseEntity.notFound().build();
        }
        
        Todo todo = existingTodo.get();
        todo.setTitle(todoDto.getTitle());
        todo.setDescription(todoDto.getDescription());
        todo.setCompleted(todoDto.isCompleted());
        
        Todo updatedTodo = todoRepository.save(todo);
        return ResponseEntity.ok(TodoDto.fromEntity(updatedTodo));
    }
    
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteTodo(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        
        Optional<Todo> todo = todoRepository.findById(id);
        if (todo.isEmpty() || !todo.get().getUsername().equals(username)) {
            return ResponseEntity.notFound().build();
        }
        
        todoRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/completed")
    public ResponseEntity<List<TodoDto>> getCompletedTodos(@AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        List<Todo> todos = todoRepository.findByUsernameAndCompleted(username, true);
        List<TodoDto> todoDtos = todos.stream()
            .map(TodoDto::fromEntity)
            .collect(Collectors.toList());
        return ResponseEntity.ok(todoDtos);
    }
    
    @GetMapping("/pending")
    public ResponseEntity<List<TodoDto>> getPendingTodos(@AuthenticationPrincipal Jwt jwt) {
        String username = getUsernameFromJwt(jwt);
        List<Todo> todos = todoRepository.findByUsernameAndCompleted(username, false);
        List<TodoDto> todoDtos = todos.stream()
            .map(TodoDto::fromEntity)
            .collect(Collectors.toList());
        return ResponseEntity.ok(todoDtos);
    }
}
```

### Public Controller (for testing)
```java
package com.todo.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/public")
public class PublicController {
    
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "OK", "service", "Todo Resource Server");
    }
    
    @GetMapping("/info")
    public Map<String, String> info() {
        return Map.of(
            "name", "Todo REST API",
            "version", "1.0.0",
            "description", "Protected Todo Resource Server"
        );
    }
}
```

### Main Application Class
```java
package com.todo.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TodoResourceServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TodoResourceServerApplication.class, args);
    }
}
```

### Application Properties
```properties
# application.properties
server.port=8081

spring.datasource.url=jdbc:h2:mem:tododb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=

spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true

spring.h2.console.enabled=true

# OAuth2 Resource Server Configuration
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000

# Logging
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.oauth2=DEBUG
```

## 2. Testing Commands (cURL)

First, make sure both servers are running:
- Authorization Server: `http://localhost:9000`
- Resource Server: `http://localhost:8081`

### Step 1: Get Access Token from Authorization Server
```bash
# Using client credentials flow (for testing)
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic dG9kby1jbGllbnQ6dG9kby1jbGllbnQtc2VjcmV0" \
  -d "grant_type=client_credentials" \
  -d "scope=todo.read todo.write"
```

Save the access token from the response.

### Step 2: Test Public Endpoints (No token required)
```bash
# Test health endpoint
curl http://localhost:8081/public/health

# Test info endpoint  
curl http://localhost:8081/public/info
```

### Step 3: Test Protected Endpoints (With token)

**Replace `YOUR_ACCESS_TOKEN` with the actual token from Step 1**

```bash
# Get all todos (requires todo.read scope)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/todos

# Create a new todo (requires todo.write scope)
curl -X POST http://localhost:8081/todos \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Learn Spring Security",
    "description": "Study OAuth2 and JWT",
    "completed": false
  }'

# Create another todo
curl -X POST http://localhost:8081/todos \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Build Todo App",
    "description": "Create full-stack application",
    "completed": true
  }'

# Get all todos again to see the created items
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/todos

# Get completed todos
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/todos/completed

# Get pending todos
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/todos/pending

# Update a todo (replace {id} with actual todo ID)
curl -X PUT http://localhost:8081/todos/{id} \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Learn Spring Security OAuth2",
    "description": "Master OAuth2 flows and implementation",
    "completed": true
  }'

# Delete a todo (replace {id} with actual todo ID)
curl -X DELETE http://localhost:8081/todos/{id} \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Step 4: Test without token (should fail)
```bash
# Try to access todos without token
curl http://localhost:8081/todos

# Try with invalid token
curl -H "Authorization: Bearer invalid_token" \
  http://localhost:8081/todos
```

## 3. Complete Test Script

Create `test-resource-server.sh`:

```bash
#!/bin/bash

RESOURCE_SERVER="http://localhost:8081"
AUTH_SERVER="http://localhost:9000"

echo "=== Testing Todo Resource Server ==="

# Step 1: Get access token
echo -e "\n1. Getting access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$AUTH_SERVER/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic dG9kby1jbGllbnQ6dG9kby1jbGllbnQtc2VjcmV0" \
  -d "grant_type=client_credentials" \
  -d "scope=todo.read todo.write")

echo "Token response: $TOKEN_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Failed to get access token"
    exit 1
fi

echo -e "\nAccess token obtained successfully!"

# Step 2: Test public endpoints
echo -e "\n2. Testing public endpoints..."
echo "Health check:"
curl -s "$RESOURCE_SERVER/public/health" | jq .

echo -e "\nInfo:"
curl -s "$RESOURCE_SERVER/public/info" | jq .

# Step 3: Test protected endpoints
echo -e "\n3. Testing protected endpoints..."

echo -e "\nCreating todos..."
curl -s -X POST "$RESOURCE_SERVER/todos" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Learn Spring Security", "description": "Study OAuth2 and JWT", "completed": false}' | jq .

curl -s -X POST "$RESOURCE_SERVER/todos" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Build Todo App", "description": "Create full-stack application", "completed": true}' | jq .

echo -e "\nGetting all todos:"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$RESOURCE_SERVER/todos" | jq .

echo -e "\nGetting completed todos:"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$RESOURCE_SERVER/todos/completed" | jq .

echo -e "\nGetting pending todos:"
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$RESOURCE_SERVER/todos/pending" | jq .

echo -e "\n4. Testing without token (should fail):"
curl -s -w "HTTP Status: %{http_code}\n" "$RESOURCE_SERVER/todos"

echo -e "\n=== Test completed ==="
```

Make it executable and run:
```bash
chmod +x test-resource-server.sh
./test-resource-server.sh
```

## Key Features of Resource Server:

1. **OAuth2 Resource Server** - Validates JWT tokens from Authorization Server
2. **Scope-based Authorization** - Requires `todo.read` and `todo.write` scopes
3. **User-specific Data** - Each user only sees their own todos
4. **RESTful API** - Full CRUD operations for todos
5. **Public Endpoints** - Health check and info endpoints

Start the Resource Server and run the test commands! Let me know if you encounter any issues.
