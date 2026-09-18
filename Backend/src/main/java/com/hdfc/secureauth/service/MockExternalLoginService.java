package com.hdfc.secureauth.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.stereotype.Service;

@Service
public class MockExternalLoginService {

    private volatile boolean serviceAvailable=true;

    @CircuitBreaker(name = "loginService", fallbackMethod = "loginFallback")
    public boolean authentication(){

        if(!serviceAvailable){
            throw new RuntimeException("Mock Service is Not available");
        }
        return true;
    }

    public boolean loginFallback(Exception e) {

        return false;
    }

    public void setServiceAvailable(boolean serviceAvailable) {
        this.serviceAvailable = serviceAvailable;
    }
}
