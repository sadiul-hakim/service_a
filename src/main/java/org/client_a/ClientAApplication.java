package org.client_a;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class ClientAApplication {
    private final OAuth2AuthorizedClientManager clientManager;

    public ClientAApplication(OAuth2AuthorizedClientManager clientManager) {
        this.clientManager = clientManager;
    }

    public static void main(String[] args) {
        SpringApplication.run(ClientAApplication.class, args);
    }
    @GetMapping("/token")
    public ResponseEntity<?> home(){
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest.withClientRegistrationId("2")
                .principal("client_b").build();
        var client = clientManager.authorize(request);

        assert client != null;
        return ResponseEntity.ok(client.getAccessToken().getTokenValue());
//        return ResponseEntity.ok("OK");
    }
    @GetMapping("/hello")
    public ResponseEntity<?> hello(){
        return ResponseEntity.ok("hello");
    }

    @GetMapping("/")
    public ResponseEntity<?> home2(){
        return ResponseEntity.ok("hello");
    }

}
