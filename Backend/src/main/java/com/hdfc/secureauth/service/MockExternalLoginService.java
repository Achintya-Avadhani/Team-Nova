package com.hdfc.secureauth.service;

import com.hdfc.secureauth.exception.ExternalServiceUnavailableException;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class MockExternalLoginService {

    private volatile boolean serviceAvailable = false;

    @CircuitBreaker(
            name = "loginService",
            fallbackMethod = "loginFallback"
    )
    public boolean authentication() {

        log.info("Calling mock external login service");

        if (!serviceAvailable) {
            throw new RuntimeException("Mock Service is Not available");
        }

        return true;
    }

    public boolean loginFallback(Exception e) {

        log.warn("Circuit breaker fallback triggered: {}", e.getMessage());

        throw new ExternalServiceUnavailableException(
                "External Login Service is currently unavailable"
        );
    }

    public void setServiceAvailable(boolean serviceAvailable) {
        this.serviceAvailable = serviceAvailable;
    }
}
