package com.hdfc.secureauth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final String CORRELATION_ID = "correlationId";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String correlationId =
                request.getHeader("X-Correlation-ID");

        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }

        MDC.put(CORRELATION_ID, correlationId);

        request.setAttribute(
                CORRELATION_ID,
                correlationId
        );

        response.setHeader(
                "X-Correlation-ID",
                correlationId
        );

        long startTime = System.currentTimeMillis();

        try {

            log.info(
                    "Incoming request: {} {}",
                    request.getMethod(),
                    request.getRequestURI()
            );

            filterChain.doFilter(
                    request,
                    response
            );

        } finally {

            long duration =
                    System.currentTimeMillis() - startTime;

            log.info(
                    "Completed request: {} {} | status={} | duration={}ms",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    duration
            );

            MDC.remove(CORRELATION_ID);
        }
    }
}