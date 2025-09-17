package com.example.demo.user;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank String identifier,   // name or email
        @NotBlank String password
) {
}
