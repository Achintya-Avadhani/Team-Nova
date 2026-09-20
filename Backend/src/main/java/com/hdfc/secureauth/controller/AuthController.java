package com.hdfc.secureauth.controller;

import com.hdfc.secureauth.dto.*;
import com.hdfc.secureauth.exception.SessionExpiredException;
import com.hdfc.secureauth.exception.TooManyLoginAttemptsException;
import com.hdfc.secureauth.service.AuthService;
import com.hdfc.secureauth.service.LoginRatelimiterService;
import com.hdfc.secureauth.util.JwtUtil;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication",
description = "APIs for user signup, login, authentication and logout")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final LoginRatelimiterService loginRatelimiterService;

    @Operation(
            summary = "Register a new user",
            description = "Creates a new user account")
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

    @Operation(
            summary = "Login user",
            description = "Authenticates the user and returns a signed JWT "
                    + "Use the Authorize button at the top of Swagger UI to provide the JWT.")
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

        LoginResponse response=authService.login(request);

        log.info(
                "Login successful for user: {}",
                request.getUsername()
        );

        return response;
    }

    @Operation(
            summary = "Refresh access token",
            description = "Generates a new access token using a valid refresh token"
    )
    @PostMapping("/refresh")
    public LoginResponse refresh(
            @RequestBody RefreshTokenRequest request) {

        log.info("Access token refresh request received");

        String accessToken =
                authService.refreshAccessToken(request.getRefreshToken());

        log.info("Access token refreshed successfully");

        return LoginResponse.builder()
                .message("Access token refreshed successfully")
                .accessToken(accessToken)
                .build();
    }

    @Operation(
            summary = "Validate JWT",
            description = "Validates the JWT and checks whether the session is still active "
                    + "Use the Authorize button at the top of Swagger UI to provide the JWT.")
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/auth")
    public AuthResponse validateToken(@Parameter(hidden = true)
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

    @Operation(
            summary = "Logout user",
            description = "Invalidates the user's current JWT session")
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping("/logout")
    public String logout(@Parameter(hidden = true)
                             @RequestHeader("Authorization") String authorizationHeader,
                            @RequestBody LogoutRequest request) {

        log.info("Logout request received");

        String accessToken = jwtUtil.extractToken(authorizationHeader);

        authService.logout(accessToken,request.getRefreshToken());

        log.info("Token removed. User logged out.");

        return "Logged out successfully";
    }
}