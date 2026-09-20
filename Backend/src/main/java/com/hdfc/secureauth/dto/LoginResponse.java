package com.hdfc.secureauth.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonPropertyOrder({
        "message",
        "user",
        "accessToken",
        "refreshToken"
})
public class LoginResponse {
    private String message;
    private String accessToken;
    private String refreshToken;
    private String user;

}
