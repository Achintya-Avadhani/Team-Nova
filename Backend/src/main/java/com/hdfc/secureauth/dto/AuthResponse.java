package com.hdfc.secureauth.dto;


import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String message;
    private String token;
    private Object user;
}
