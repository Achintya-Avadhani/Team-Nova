package com.hdfc.secureauth.service;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginRatelimiterService {
    private final int userlimit;
    private final int iplimit;
    private final Duration refreshPeriod;

    private final ConcurrentHashMap<String, RateLimiter> userLimiters =
            new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, RateLimiter> ipLimiters =
            new ConcurrentHashMap<>();

    public LoginRatelimiterService(
            @Value("${login.rate-limit.user-limit}") int userLimit,
            @Value("${login.rate-limit.ip-limit}") int ipLimit,
            @Value("${login.rate-limit.refresh-period-seconds}") long refreshPeriodSeconds) {

        this.userlimit = userLimit;
        this.iplimit = ipLimit;
        this.refreshPeriod = Duration.ofSeconds(refreshPeriodSeconds);
    }

    public boolean checkLoginAttempt(String username, String ipAddress) {

        RateLimiter userRateLimiter =
                userLimiters.computeIfAbsent(
                        username,
                        key -> createRateLimiter("user-" + key, userlimit)
                );

        RateLimiter ipRateLimiter =
                ipLimiters.computeIfAbsent(
                        ipAddress,
                        key -> createRateLimiter("ip-" + key, iplimit)
                );

        if (!userRateLimiter.acquirePermission()) {
            return false;
        }

        if (!ipRateLimiter.acquirePermission()) {
            return false;
        }

        return true;
    }

    private RateLimiter createRateLimiter(String name, int limit) {

        RateLimiterConfig config =
                RateLimiterConfig.custom()
                        .limitForPeriod(limit)
                        .limitRefreshPeriod(refreshPeriod)
                        .timeoutDuration(Duration.ZERO)
                        .build();

        return RateLimiter.of(name, config);
    }

}
