package com.hdfc.secureauth;

import com.hdfc.secureauth.dto.LoginRequest;
import com.hdfc.secureauth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class SecureAuthResilienceApplicationTests {

	@Autowired
	private AuthService authService;

	@Test
	void contextLoads() {
	}

	@Test
	void signUpShouldAllowNewUserToLogin() {
		LoginRequest request = new LoginRequest();
		request.setUsername("newuser");
		request.setPassword("newpass123");

		String token = assertDoesNotThrow(() -> authService.signup(request));
		assertNotNull(token);
		assertDoesNotThrow(() -> authService.login(request));
	}

}
