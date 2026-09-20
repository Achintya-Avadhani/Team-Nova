package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.dto.LoginResponse;
import com.hdfc.secureauth.entity.User;
import com.hdfc.secureauth.exception.ApiException;
import com.hdfc.secureauth.exception.InvalidCredentialsException;
import com.hdfc.secureauth.exception.InvalidTokenException;
import com.hdfc.secureauth.repository.InMemoryRefreshTokenStore;
import com.hdfc.secureauth.repository.InMemoryTokenStore;
import com.hdfc.secureauth.repository.UserRepository;
import com.hdfc.secureauth.util.JwtUtil;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final JwtUtil jwtUtil;
    private final InMemoryTokenStore tokenStore;
    private final MockExternalLoginService mockExternalLoginService;
    private final UserRepository userRepository;
    private final InMemoryRefreshTokenStore refreshTokenStore;

    //signup
    public void signup(LoginRequest request) {
        validateRequest(request);

        String username = request.getUsername();

        if (userRepository.existsById(username)) {
            log.warn("Signup failed. User already exists: {}", username);
            throw new ApiException("User already exists");
        }

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(request.getPassword());

        userRepository.save(newUser);

        log.info("New user registered: {}", username);
    }

//login
    public LoginResponse login(LoginRequest request) {
        validateRequest(request);

        User user = userRepository.findById(request.getUsername())
                .orElseThrow(() -> {
                    log.warn("Invalid login attempt for user: {}", request.getUsername());
                    return new InvalidCredentialsException("Invalid username or password");
                });

        if (!user.getPassword().equals(request.getPassword())) {
            log.warn("Invalid password for user: {}", request.getUsername());
            throw new InvalidCredentialsException("Invalid username or password");
        }

        log.info("Credentials validated for user: {}", request.getUsername());

        return createTokens(request.getUsername());
    }

    private LoginResponse createTokens(String username) {

        log.debug("Calling external authentication service for user: {}", username);

        boolean externalLoginSuccess = mockExternalLoginService.authentication();

        if (!externalLoginSuccess) {
            log.error("External Login Service failed for user: {}", username);
            throw new ApiException("External Login Service Failed");
        }

        String accessToken = jwtUtil.generateaccessToken(username);

        String refreshToken = jwtUtil.generateRefreshToken(username);

        tokenStore.addToken(accessToken);
        refreshTokenStore.addToken(refreshToken, username);


        log.info("Token generated & stored for user: {}", username);

        return LoginResponse.builder()
                .message("Login successful")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .user(username)
                .build();
    }

    private void validateRequest(LoginRequest request) {

        if (request == null ||
                request.getUsername() == null ||
                request.getPassword() == null ||
                request.getUsername().isBlank() ||
                request.getPassword().isBlank()
        ) {
            throw new ApiException("Username and password are required");
        }
    }

    public boolean validate(String token) {

        if (token == null || token.isBlank()) {
            throw new InvalidTokenException("Token is missing");
        }

        boolean valid = tokenStore.contains(token);

        log.debug("Token validation result: {}", valid);

        return valid;
    }

    //logout
    public void logout(String accessToken, String refreshToken) {

        if (accessToken == null || accessToken.isBlank()) {
            throw new InvalidTokenException("Access token is missing");
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token is missing");
        }

        tokenStore.remove(accessToken);
        refreshTokenStore.remove(refreshToken);

        log.info("Access token and refresh token removed. User logged out.");
    }

    //refresh token
    public LoginResponse refreshAccessToken(String refreshToken) {

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token is missing");
        }

        try {

            var parsedToken =
                    jwtUtil.validateRefreshToken(refreshToken);

            String username =
                    parsedToken.getBody().getSubject();

            if (!refreshTokenStore.contains(refreshToken)) {
                log.warn("Refresh token not found in active store");

                throw new InvalidTokenException(
                        "Invalid or expired refresh token"
                );
            }

            String newAccessToken =
                    jwtUtil.generateaccessToken(username);

            String newRefreshToken =
                    jwtUtil.generateRefreshToken(username);

            refreshTokenStore.remove(refreshToken);

            tokenStore.addToken(newAccessToken);

            refreshTokenStore.addToken(
                    newRefreshToken,
                    username
            );

            log.info(
                    "Access and refresh tokens refreshed for user: {}",
                    username
            );


            return LoginResponse.builder()
                    .message("Tokens refreshed successfully")
                    .user(username)
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();

        } catch (JwtException e) {

            log.warn("Invalid refresh JWT received");

            throw new InvalidTokenException(
                    "Invalid or expired refresh token"
            );
        }
    }
}