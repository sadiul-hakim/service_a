package org.client_a.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

@Configuration
public class AppConfig {
    @Value("${service_a.client_id}")
    private String CLIENT_A_ID;
    @Value("${service_a.client_secret}")
    private String CLIENT_A_SECRET;
    @Value("${service_b.client_id}")
    private String CLIENT_B_ID;
    @Value("${service_b.client_secret}")
    private String CLIENT_B_SECRET;
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    @Bean
    public SecurityFilterChain config(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.oauth2Login(Customizer.withDefaults()) // TODO (TWO): here
                .oauth2Client(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth.requestMatchers("/token").permitAll())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        ClientRegistration client_b = ClientRegistration.withRegistrationId("2")
                .clientId(CLIENT_B_ID)
                .clientSecret(CLIENT_B_SECRET)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("http://localhost:9090/oauth2/token")
                .scope(OidcScopes.OPENID)
                .build();
        ClientRegistration client_a = ClientRegistration.withRegistrationId("1")
                .clientId(CLIENT_A_ID)
                .clientSecret(CLIENT_A_SECRET)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:9096/login/oauth2/code/Authorization_Server")
                .scope(OidcScopes.OPENID)
                .authorizationUri("http://localhost:9090/oauth2/authorize")
                .tokenUri("http://localhost:9090/oauth2/token")
                .build();
        return new InMemoryClientRegistrationRepository(client_a,client_b);
    }

    @Bean
    public OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
                                                                       OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository){
        var provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .build();
        var cm = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, oAuth2AuthorizedClientRepository);
        cm.setAuthorizedClientProvider(provider);
        return cm;
    }
}
