package com.hdfc.secureauth.repository;


import org.springframework.stereotype.Component;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryTokenStore {
    private final Set<String> validTokens= ConcurrentHashMap.newKeySet();

    public void addToken(String token){
        validTokens.add(token);
    }

    public boolean contains(String token) {
        return validTokens.contains(token);
    }

    public void remove(String token) {
        validTokens.remove(token);
    }
}
