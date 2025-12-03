package com.rs.auth.controller;

import com.nimbusds.jose.KeySourceException;
import com.rs.auth.dto.*;
import com.rs.auth.jwt.JwtTokenGenerator;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class AuthController {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final JdbcUserDetailsManager jdbcUserDetailsManager;
    private final JwtTokenGenerator jwtTokenGenerator;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

        if (jdbcUserDetailsManager.userExists(request.getUsername())) {
            return ResponseEntity.badRequest().body("Username already exists");
        }

        UserDetails user = User.withUsername(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles("USER")
                .build();

        jdbcUserDetailsManager.createUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) throws KeySourceException {
        UserDetails user = userDetailsService.loadUserByUsername(request.getUsername());

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        String token = jwtTokenGenerator.generateToken(user);

        return ResponseEntity.ok(new TokenResponse(token));
    }
}
