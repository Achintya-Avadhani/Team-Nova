package com.hdfc.secureauth.util;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class AuthCookieUtil {

    public static final String ACCESS_TOKEN_COOKIE = "accessToken";
    public static final String REFRESH_TOKEN_COOKIE = "refreshToken";

    private static final Duration ACCESS_TOKEN_MAX_AGE =
            Duration.ofMinutes(10);

    private static final Duration REFRESH_TOKEN_MAX_AGE =
            Duration.ofHours(1);

    public ResponseCookie createAccessTokenCookie(String token) {
        return ResponseCookie.from(ACCESS_TOKEN_COOKIE, token)
                .httpOnly(true)
                .secure(false)       // localhost HTTP; set true in production HTTPS
                .sameSite("Lax")
                .path("/")
                .maxAge(ACCESS_TOKEN_MAX_AGE)
                .build();
    }

    public ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, token)
                .httpOnly(true)
                .secure(false)       // localhost HTTP; set true in production HTTPS
                .sameSite("Lax")
                .path("/")
                .maxAge(REFRESH_TOKEN_MAX_AGE)
                .build();
    }

    public ResponseCookie deleteAccessTokenCookie() {
        return ResponseCookie.from(ACCESS_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
    }

    public ResponseCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
    }
}