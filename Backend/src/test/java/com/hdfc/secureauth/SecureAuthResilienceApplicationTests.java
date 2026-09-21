package com.hdfc.secureauth;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.dto.LoginResponse;
import com.hdfc.secureauth.exception.ApiException;
import com.hdfc.secureauth.exception.InvalidCredentialsException;
import com.hdfc.secureauth.exception.InvalidTokenException;
import com.hdfc.secureauth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class SecureAuthResilienceApplicationTests {

	@Autowired
	private AuthService authService;

	@Test
	void contextLoads() {
	}

	@Test
	void signUpShouldAllowNewUserToLogin() {
		LoginRequest request = requestFor(uniqueUsername("newuser"), "newpass123");

		assertDoesNotThrow(() -> authService.signup(request));
		assertDoesNotThrow(() -> authService.login(request));
	}

	@Test
	void loginShouldRejectIncorrectPassword() {
		LoginRequest signupRequest = requestFor(uniqueUsername("wrong-password-user"), "correct-pass123");
		authService.signup(signupRequest);

		LoginRequest loginRequest = new LoginRequest();
		loginRequest.setUsername(signupRequest.getUsername());
		loginRequest.setPassword("incorrect-pass123");

		assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));
	}

	@Test
	void signupShouldRejectDuplicateUser() {
		LoginRequest request = requestFor(uniqueUsername("duplicate-user"), "password123");
		authService.signup(request);

		ApiException exception = assertThrows(ApiException.class, () -> authService.signup(request));

		assertEquals("User already exists", exception.getMessage());
	}

	@Test
	void signupShouldRejectMissingCredentials() {
		assertThrows(ApiException.class, () -> authService.signup(null));

		LoginRequest blankRequest = requestFor("", "");
		assertThrows(ApiException.class, () -> authService.signup(blankRequest));
	}

	@Test
	void loginShouldRejectUnknownUser() {
		LoginRequest request = requestFor(uniqueUsername("unknown-user"), "password123");

		assertThrows(InvalidCredentialsException.class, () -> authService.login(request));
	}

	@Test
	void loginShouldCreateValidAccessAndRefreshTokens() {
		LoginRequest request = requestFor(uniqueUsername("token-user"), "password123");
		authService.signup(request);

		LoginResponse response = authService.login(request);

		assertEquals(request.getUsername(), response.getUser());
		assertNotNull(response.getAccessToken());
		assertNotNull(response.getRefreshToken());
		assertTrue(authService.validate(response.getAccessToken()));
	}

	@Test
	void validateShouldRejectMissingToken() {
		assertThrows(InvalidTokenException.class, () -> authService.validate(null));
		assertThrows(InvalidTokenException.class, () -> authService.validate(" "));
	}

	@Test
	void validateShouldReturnFalseForUnknownToken() {
		assertFalse(authService.validate("unknown-token"));
	}

	@Test
	void logoutShouldInvalidateAccessAndRefreshTokens() {
		LoginResponse response = loginUser(uniqueUsername("logout-user"));

		authService.logout(response.getAccessToken(), response.getRefreshToken());

		assertFalse(authService.validate(response.getAccessToken()));
		assertThrows(InvalidTokenException.class,
				() -> authService.refreshAccessToken(response.getRefreshToken()));
	}

	@Test
	void logoutShouldRejectMismatchedAccessToken() {
		LoginResponse response = loginUser(uniqueUsername("mismatched-logout-user"));

		InvalidTokenException exception = assertThrows(
				InvalidTokenException.class,
				() -> authService.logout("different-access-token", response.getRefreshToken()));

		assertEquals("Access token does not match active session", exception.getMessage());
	}

	@Test
	void refreshShouldRotateTokensAndInvalidateOldSession() {
		LoginResponse originalResponse = loginUser(uniqueUsername("refresh-user"));

		LoginResponse refreshedResponse = authService.refreshAccessToken(originalResponse.getRefreshToken());

		assertEquals(originalResponse.getUser(), refreshedResponse.getUser());
		assertNotNull(refreshedResponse.getAccessToken());
		assertNotNull(refreshedResponse.getRefreshToken());
		assertFalse(originalResponse.getRefreshToken().equals(refreshedResponse.getRefreshToken()));
		assertTrue(authService.validate(refreshedResponse.getAccessToken()));
		assertThrows(InvalidTokenException.class,
				() -> authService.refreshAccessToken(originalResponse.getRefreshToken()));
	}

	@Test
	void refreshShouldRejectMissingOrMalformedToken() {
		assertThrows(InvalidTokenException.class, () -> authService.refreshAccessToken(null));
		assertThrows(InvalidTokenException.class, () -> authService.refreshAccessToken("malformed-token"));
	}

	private LoginResponse loginUser(String username) {
		LoginRequest request = requestFor(username, "password123");
		authService.signup(request);
		return authService.login(request);
	}

	private LoginRequest requestFor(String username, String password) {
		LoginRequest request = new LoginRequest();
		request.setUsername(username);
		request.setPassword(password);
		return request;
	}

	private String uniqueUsername(String prefix) {
		return prefix + "-" + UUID.randomUUID();
	}

}
