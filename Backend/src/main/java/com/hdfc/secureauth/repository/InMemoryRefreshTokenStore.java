package com.hdfc.secureauth.repository;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryRefreshTokenStore {
    private final ConcurrentHashMap<String, RefreshTokenSession> refreshTokens =
            new ConcurrentHashMap<>();

    public void addToken(
            String refreshToken,
            String username,
            String accessToken) {

        refreshTokens.put(
                refreshToken,
                new RefreshTokenSession(username, accessToken)
        );
    }

    public RefreshTokenSession getSession(String refreshToken) {
        return refreshTokens.get(refreshToken);
    }

    public boolean contains(String refreshToken) {
        return refreshTokens.containsKey(refreshToken);
    }

    public void remove(String refreshToken) {
        refreshTokens.remove(refreshToken);
    }
}
