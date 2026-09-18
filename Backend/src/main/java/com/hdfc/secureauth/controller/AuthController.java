package com.hdfc.secureauth.controller;

import com.hdfc.secureauth.dto.AuthResponse;
import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.dto.LoginResponse;
import com.hdfc.secureauth.exception.SessionExpiredException;
import com.hdfc.secureauth.exception.TooManyLoginAttemptsException;
import com.hdfc.secureauth.service.AuthService;
import com.hdfc.secureauth.service.LoginRatelimiterService;
import com.hdfc.secureauth.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final LoginRatelimiterService loginRatelimiterService;

    @PostMapping("/signup")
    public AuthResponse signup(
            @Valid @RequestBody LoginRequest request) {

        log.info(
                "Signup attempt for user: {}",
                request.getUsername()
        );

        authService.signup(request);

        log.info(
                "User registered successfully: {}",
                request.getUsername()
        );

        return AuthResponse.builder()
                .message("User registered successfully")
                .user(request.getUsername())
                .build();
    }

    @PostMapping("/login")
    public LoginResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        log.info(
                "Login attempt for user: {}",
                request.getUsername()
        );

        String ipAddress = httpRequest.getRemoteAddr();

        boolean allowed = loginRatelimiterService.checkLoginAttempt(
                request.getUsername(),
                ipAddress
        );

        if (!allowed) {
            log.warn(
                    "Login rate limit exceeded for user: {} from IP: {}",
                    request.getUsername(),
                    ipAddress
            );

            throw new TooManyLoginAttemptsException(
                    "Too many login attempts. Please try again later."
            );
        }

        String token = authService.login(request);

        log.info(
                "Login successful for user: {}",
                request.getUsername()
        );

        return LoginResponse.builder()
                .message("Login successful")
                .token("Bearer " + token)
                .user(request.getUsername())
                .build();
    }

    @GetMapping("/auth")
    public AuthResponse validateToken(
            @RequestHeader("Authorization") String authorizationHeader) {

        log.info("Token validation request received");

        String token = jwtUtil.extractToken(authorizationHeader);

        var parsedToken = jwtUtil.validateToken(token);

        boolean isValid = authService.validate(token);

        if (!isValid) {

            log.warn(
                    "Token not found in memory. Session expired."
            );

            throw new SessionExpiredException(
                    "Session expired or invalid token"
            );
        }

        String username = parsedToken.getBody().getSubject();

        log.info(
                "Token valid for user: {}",
                username
        );

        return AuthResponse.builder()
                .message("Token is valid")
                .user(username)
                .build();
    }

    @PostMapping("/logout")
    public String logout(
            @RequestHeader("Authorization") String authorizationHeader) {

        log.info("Logout request received");

        String token = jwtUtil.extractToken(authorizationHeader);

        authService.logout(token);

        log.info("Token removed. User logged out.");

        return "Logged out successfully";
    }
}