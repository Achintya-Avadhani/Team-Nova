package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.model.InMemoryTokenStore;
import com.hdfc.secureauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;                   // Handles token generation + validation
    private final InMemoryTokenStore tokenStore;     // Stores active tokens in memory

    // Hardcoded credentials (project requirement)
    private final String VALID_USERNAME = "admin";
    private final String VALID_PASSWORD = "password123";


    public String login(LoginRequest request) {
        if (request.getUsername().equals(VALID_USERNAME)
                && request.getPassword().equals(VALID_PASSWORD)) {

            // Generate JWT token
            String token = jwtUtil.generateToken(request.getUsername());

            // Save token in memory
            tokenStore.addToken(token);
            return token;
        }
        throw new RuntimeException("Invalid username or password");
    }





    public boolean validate(String token) {
        return tokenStore.contains(token);   // checks if token exists in memory
    }



    public void logout(String token) {
        tokenStore.remove(token);            // removes token from memory
    }
}