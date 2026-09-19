package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.entity.User;
import com.hdfc.secureauth.exception.ApiException;
import com.hdfc.secureauth.exception.InvalidCredentialsException;
import com.hdfc.secureauth.exception.InvalidTokenException;
import com.hdfc.secureauth.repository.InMemoryTokenStore;
import com.hdfc.secureauth.repository.UserRepository;
import com.hdfc.secureauth.util.JwtUtil;

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

    // ✅ NEW: Use PostgreSQL repository instead of in-memory map
    private final UserRepository userRepository;


    /**
     * =========================================================================
     * ✅ SIGNUP
     * =========================================================================
     */
    public void signup(LoginRequest request) {
        validateRequest(request);

        String username = request.getUsername();

        // ✅ Check if user already exists in DB
        if (userRepository.existsById(username)) {
            log.warn("Signup failed. User already exists: {}", username);
            throw new ApiException("User already exists");
        }

        // ✅ Create User entity and save in PostgreSQL
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(request.getPassword()); // (Plaintext — later we add BCrypt)

        userRepository.save(newUser);

        log.info("New user registered: {}", username);
    }



    /**
     * =========================================================================
     * ✅ LOGIN
     * =========================================================================
     */
    public String login(LoginRequest request) {
        validateRequest(request);

        // ✅ Fetch user from DB
        User user = userRepository.findById(request.getUsername())
                .orElseThrow(() -> {
                    log.warn("Invalid login attempt for user: {}", request.getUsername());
                    return new InvalidCredentialsException("Invalid username or password");
                });

        // ✅ Compare passwords
        if (!user.getPassword().equals(request.getPassword())) {
            log.warn("Invalid password for user: {}", request.getUsername());
            throw new InvalidCredentialsException("Invalid username or password");
        }

        log.info("Credentials validated for user: {}", request.getUsername());

        return createToken(request.getUsername());
    }



    /**
     * =========================================================================
     * ✅ TOKEN CREATION (JWT + External Service Check)
     * =========================================================================
     */
    private String createToken(String username) {

        log.debug("Calling external authentication service for user: {}", username);

        boolean externalLoginSuccess = mockExternalLoginService.authentication();

        if (!externalLoginSuccess) {
            log.error("External Login Service failed for user: {}", username);
            throw new ApiException("External Login Service Failed");
        }

        // ✅ Generate JWT
        String token = jwtUtil.generateToken(username);

        // ✅ Store token in in-memory session store
        tokenStore.addToken(token);

        log.info("Token generated & stored for user: {}", username);

        return token;
    }



    /**
     * =========================================================================
     * ✅ REQUEST VALIDATION
     * =========================================================================
     */
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



    /**
     * =========================================================================
     * ✅ TOKEN VALIDATION (/auth)
     * =========================================================================
     */
    public boolean validate(String token) {

        if (token == null || token.isBlank()) {
            throw new InvalidTokenException("Token is missing");
        }

        boolean valid = tokenStore.contains(token);

        log.debug("Token validation result: {}", valid);

        return valid;
    }



    /**
     * =========================================================================
     * ✅ LOGOUT
     * =========================================================================
     */
    public void logout(String token) {

        if (token == null || token.isBlank()) {
            throw new InvalidTokenException("Token is missing");
        }

        tokenStore.remove(token);

        log.info("Token removed from active token store.");
    }
}