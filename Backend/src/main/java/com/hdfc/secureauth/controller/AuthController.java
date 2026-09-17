package com.hdfc.secureauth.controller;

import com.hdfc.secureauth.dto.AuthResponse;
import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.service.AuthService;
import com.hdfc.secureauth.util.JwtUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;


    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {
        log.info("Login attempt for user: {}", request.getUsername());
        String token = authService.login(request);
        log.info("Login successful. Token generated.");

        return AuthResponse.builder()
                .message("Login successful")
                .token(token)
                .build();
    }




    @GetMapping("/auth")
    public AuthResponse validateToken(@RequestHeader("Authorization") String token) {
        log.info("Token validation request received");
        var parsedToken = jwtUtil.validateToken(token);

        // Check if token still exists in memory (session alive)
        boolean isValid = authService.validate(token);
        if (!isValid) {
            log.warn("Token not found in memory. Session expired.");
            throw new RuntimeException("Session expired or invalid token");
        }

        String username = parsedToken.getBody().getSubject();
        log.info("Token valid for user: {}", username);

        return AuthResponse.builder()
                .message("Token is valid")
                .user(username)
                .build();
    }




    @PostMapping("/logout")
    public AuthResponse logout(@RequestHeader("Authorization") String token) {
        log.info("Logout request received");
        authService.logout(token);
        log.info("Token removed. User logged out.");

        return AuthResponse.builder()
                .message("Logged out successfully")
                .build();
    }
}