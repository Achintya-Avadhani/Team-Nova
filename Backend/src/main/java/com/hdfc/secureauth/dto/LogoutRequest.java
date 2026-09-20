package com.hdfc.secureauth.dto;

import lombok.Data;

@Data
public class LogoutRequest {
    private String refreshToken;
}
