package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.exception.ApiException;
import com.hdfc.secureauth.exception.InvalidCredentialsException;
import com.hdfc.secureauth.exception.InvalidTokenException;
import com.hdfc.secureauth.repository.InMemoryTokenStore;
import com.hdfc.secureauth.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtUtil jwtUtil;
    private final InMemoryTokenStore tokenStore;
    private final MockExternalLoginService mockExternalLoginService;

    private final Map<String, String> registeredUsers =
            new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeDefaults() {

        registeredUsers.putIfAbsent(
                "admin",
                "password123"
        );

        log.info("Default admin user initialized");
    }

    public void signup(LoginRequest request) {

        validateRequest(request);

        String username = request.getUsername();

        if (registeredUsers.containsKey(username)) {

            log.warn(
                    "Signup failed. User already exists: {}",
                    username
            );

            throw new ApiException(
                    "User already exists"
            );
        }

        registeredUsers.put(
                username,
                request.getPassword()
        );

        log.info(
                "New user registered: {}",
                username
        );
    }

    public String login(LoginRequest request) {

        validateRequest(request);

        String storedPassword =
                registeredUsers.get(request.getUsername());

        if (storedPassword != null
                && storedPassword.equals(request.getPassword())) {

            log.info(
                    "Credentials validated for user: {}",
                    request.getUsername()
            );

            return createToken(request.getUsername());
        }

        log.warn(
                "Invalid login credentials for user: {}",
                request.getUsername()
        );

        throw new InvalidCredentialsException(
                "Invalid username or password"
        );
    }

    private String createToken(String username) {

        log.debug(
                "Calling external authentication service for user: {}",
                username
        );

        boolean externalLoginSuccess =
                mockExternalLoginService.authentication();

        if (!externalLoginSuccess) {

            log.error(
                    "External Login Service failed for user: {}",
                    username
            );

            throw new ApiException(
                    "External Login Service Failed"
            );
        }

        String token = jwtUtil.generateToken(username);

        tokenStore.addToken(token);

        log.info(
                "Token generated and stored for user: {}",
                username
        );

        return token;
    }

    private void validateRequest(LoginRequest request) {

        if (request == null
                || request.getUsername() == null
                || request.getPassword() == null
                || request.getUsername().isBlank()
                || request.getPassword().isBlank()) {

            throw new ApiException(
                    "Username and password are required"
            );
        }
    }

    public boolean validate(String token) {

        if (token == null || token.isBlank()) {

            throw new InvalidTokenException(
                    "Token is missing"
            );
        }

        boolean valid = tokenStore.contains(token);

        log.debug(
                "Token memory validation result: {}",
                valid
        );

        return valid;
    }

    public void logout(String token) {

        if (token == null || token.isBlank()) {

            throw new InvalidTokenException(
                    "Token is missing"
            );
        }

        tokenStore.remove(token);

        log.info("Token removed from active token store");
    }
}