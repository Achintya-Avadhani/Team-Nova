package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.repository.InMemoryTokenStore;
import com.hdfc.secureauth.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtil jwtUtil;                   // Handles token generation + validation
    private final InMemoryTokenStore tokenStore;     // Stores active tokens in memory
    private final MockExternalLoginService mockExternalLoginService;    // MockLogin Service
    private final Map<String, String> registeredUsers = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeDefaults() {
        registeredUsers.putIfAbsent("admin", "password123");
    }

    public void signup(LoginRequest request) {
        validateRequest(request);

        String username = request.getUsername();
        if (registeredUsers.containsKey(username)) {
            throw new RuntimeException("User already exists");
        }

        registeredUsers.put(username, request.getPassword());
    }

    public String login(LoginRequest request) {
        validateRequest(request);

        String storedPassword = registeredUsers.get(request.getUsername());
        if (storedPassword != null && storedPassword.equals(request.getPassword())) {
            return createToken(request.getUsername());
        }

        throw new RuntimeException("Invalid username or password");
    }

    private String createToken(String username) {
        boolean externalLoginSuccess = mockExternalLoginService.authentication();
        if (!externalLoginSuccess) {
            throw new RuntimeException("External Login Service Failed");
        }

        String token = jwtUtil.generateToken(username);
        tokenStore.addToken(token);
        return token;
    }

    private void validateRequest(LoginRequest request) {
        if (request == null || request.getUsername() == null || request.getPassword() == null
                || request.getUsername().isBlank() || request.getPassword().isBlank()) {
            throw new RuntimeException("Username and password are required");
        }
    }

    public boolean validate(String token) {
        return tokenStore.contains(token);   // checks if token exists in memory
    }

    public void logout(String token) {
        tokenStore.remove(token);            // removes token from memory
    }
}