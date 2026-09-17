package com.hdfc.secureauth.service;

import com.hdfc.secureauth.dto.LoginRequest;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import org.springframework.stereotype.Service;

@Service
public class MockExternalLoginService {

    private boolean serviceAvailable=true;

    @RateLimiter(name = "loginRateLimiter")
    @CircuitBreaker(name = "loginService", fallbackMethod = "loginFallback")
    public boolean authentication(){

        System.out.println(">>> MOCK SERVICE METHOD CALLED");

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
