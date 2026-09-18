package com.hdfc.secureauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
public class ErrorResponse {

    private Instant timestamp;
    private int statusCode;
    private String error;
    private String message;
    private String path;
    private String correlationId;
}