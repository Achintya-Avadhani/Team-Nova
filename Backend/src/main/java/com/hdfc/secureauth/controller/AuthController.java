package com.hdfc.secureauth.controller;

import com.hdfc.secureauth.dto.AuthResponse;
import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.dto.LoginResponse;
import com.hdfc.secureauth.exception.SessionExpiredException;
import com.hdfc.secureauth.exception.TooManyLoginAttemptsException;
import com.hdfc.secureauth.service.AuthService;
import com.hdfc.secureauth.service.LoginRatelimiterService;
import com.hdfc.secureauth.util.AuthCookieUtil;
import com.hdfc.secureauth.util.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
@io.swagger.v3.oas.annotations.tags.Tag(
        name = "Authentication",
        description = "APIs for user signup, login, authentication and logout"
)
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final LoginRatelimiterService loginRatelimiterService;
    private final AuthCookieUtil authCookieUtil;

    @Operation(
            summary = "Register a new user",
            description = "Creates a new user account"
    )
    @PostMapping("/signup")
    public AuthResponse signup(
            @Valid @RequestBody LoginRequest request) {

        log.info("Signup attempt for user: {}", request.getUsername());

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
            description = "Authenticates the user and stores access and refresh tokens in HttpOnly cookies."
    )
    @PostMapping("/login")
    public LoginResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

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

        LoginResponse serviceResponse =
                authService.login(request);

        setAuthenticationCookies(
                serviceResponse,
                httpResponse
        );

        log.info(
                "Login successful for user: {}",
                request.getUsername()
        );

        return LoginResponse.builder()
                .message(serviceResponse.getMessage())
                .user(serviceResponse.getUser())
                .build();
    }

    @Operation(
            summary = "Refresh access token",
            description = "Generates new access and refresh tokens using the refresh token stored in an HttpOnly cookie."
    )
    @PostMapping("/refresh")
    public LoginResponse refresh(
            @CookieValue(
                    name = AuthCookieUtil.REFRESH_TOKEN_COOKIE,
                    required = false
            )
            String refreshToken,
            HttpServletResponse httpResponse) {

        log.info("Access token refresh request received");

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new com.hdfc.secureauth.exception.InvalidTokenException(
                    "Refresh token is missing"
            );
        }

        LoginResponse serviceResponse =
                authService.refreshAccessToken(refreshToken);

        setAuthenticationCookies(
                serviceResponse,
                httpResponse
        );

        log.info(
                "Access and refresh tokens refreshed successfully"
        );

        return LoginResponse.builder()
                .message(serviceResponse.getMessage())
                .user(serviceResponse.getUser())
                .build();
    }

    @Operation(
            summary = "Validate JWT",
            description = "Validates the access token stored in the HttpOnly cookie."
    )
    @GetMapping("/auth")
    public AuthResponse validateToken(
            @CookieValue(
                    name = AuthCookieUtil.ACCESS_TOKEN_COOKIE,
                    required = false
            )
            String accessToken) {

        log.info("Token validation request received");

        if (accessToken == null || accessToken.isBlank()) {
            throw new com.hdfc.secureauth.exception.InvalidTokenException(
                    "Access token is missing"
            );
        }

        var parsedToken =
                jwtUtil.validateaccessToken(accessToken);

        boolean isValid =
                authService.validate(accessToken);

        if (!isValid) {

            log.warn(
                    "Token not found in memory. Session expired."
            );

            throw new SessionExpiredException(
                    "Session expired or invalid token"
            );
        }

        String username =
                parsedToken.getBody().getSubject();

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
            description = "Invalidates the user's current access and refresh token session."
    )
    @PostMapping("/logout")
    public String logout(
            @CookieValue(
                    name = AuthCookieUtil.ACCESS_TOKEN_COOKIE,
                    required = false
            )
            String accessToken,
            @CookieValue(
                    name = AuthCookieUtil.REFRESH_TOKEN_COOKIE,
                    required = false
            )
            String refreshToken,
            HttpServletResponse httpResponse) {

        log.info("Logout request received");

        authService.logout(
                accessToken,
                refreshToken
        );

        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                authCookieUtil.deleteAccessTokenCookie().toString()
        );

        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                authCookieUtil.deleteRefreshTokenCookie().toString()
        );

        log.info(
                "Access token and refresh token cookies cleared."
        );

        return "Logged out successfully";
    }

    private void setAuthenticationCookies(
            LoginResponse response,
            HttpServletResponse httpResponse) {

        ResponseCookie accessCookie =
                authCookieUtil.createAccessTokenCookie(
                        response.getAccessToken()
                );

        ResponseCookie refreshCookie =
                authCookieUtil.createRefreshTokenCookie(
                        response.getRefreshToken()
                );

        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                accessCookie.toString()
        );

        httpResponse.addHeader(
                HttpHeaders.SET_COOKIE,
                refreshCookie.toString()
        );
    }
}