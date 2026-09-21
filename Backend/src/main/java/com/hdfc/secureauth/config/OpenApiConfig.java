package com.hdfc.secureauth.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Secure Authentication API",
                version = "1.0",
                description = "API documentation for the Secure Authentication project"
        )
)
public class OpenApiConfig {

}
