package com.rs.auth.controller;

import com.rs.auth.dto.APIErrorResponse;
import com.rs.auth.dto.APIResponse;
import com.rs.auth.dto.ClientRegisterRequest;
import com.rs.auth.dto.ClientRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/clients")
public class ClientRegistrationController {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientRegistrationController(RegisteredClientRepository registeredClientRepository,
                                        PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<APIResponse> registerClient(@RequestBody
                                                      ClientRegisterRequest registerRequest) {
        // Generate clientId & secret
        RegisteredClient existing = registeredClientRepository.findByClientId(registerRequest.clientId());
        if (existing != null) {

            return
                    ResponseEntity.badRequest()
                            .body(new APIResponse(APIResponse.Message.FAILED,
                                    new APIErrorResponse("Client already exists",
                                            101)));
        }

        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(registerRequest.clientId())
                .clientSecret(passwordEncoder.encode(registerRequest.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(new AuthorizationGrantType(registerRequest
                        .grantTypes().getFirst()))
                .scopes(scopes -> scopes.addAll(registerRequest.scopes()))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();

        registeredClientRepository.save(client);


        // Return clientId & secret to the user
        return
                ResponseEntity.
                        ok(new
                                APIResponse(APIResponse.Message.SUCCESS,
                                Map.of("message", "Client Registered Successfully")));

    }


    @PostMapping("/register-client")
    public ResponseEntity<APIResponse> register(@RequestBody ClientRequest req) {

        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId(req.clientId())
                .clientSecret(passwordEncoder.encode(req.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();

        registeredClientRepository.save(client);

        return
                ResponseEntity.
                        ok(new APIResponse(APIResponse.Message.SUCCESS,
                                Map.of("message", "Client registered")));
    }

}
