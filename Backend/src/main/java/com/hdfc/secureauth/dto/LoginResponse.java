package com.hdfc.secureauth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "message",
        "user"
})
public class LoginResponse {

    private String message;
    private String user;

    /*
     * These fields are still temporarily used internally by AuthService.
     * They will NOT be returned to the frontend because the controller
     * will place them into HttpOnly cookies.
     */
    private String accessToken;
    private String refreshToken;
}