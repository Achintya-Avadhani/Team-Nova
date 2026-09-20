package com.hdfc.secureauth.repository;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryRefreshTokenStore {
    private final ConcurrentHashMap<String, String> refreshTokens =
            new ConcurrentHashMap<>();

    public void addToken(String token, String username) {
        refreshTokens.put(token, username);
    }

    public String getUsername(String token) {
        return refreshTokens.get(token);
    }

    public boolean contains(String token) {
        return refreshTokens.containsKey(token);
    }

    public void remove(String token) {
        refreshTokens.remove(token);
    }
}
