package com.example.demo.user;

/**
 * Authenticated user identity extracted from the JWT.
 */
public record JwtPrincipal(String userId, String name, String email, String role) {
}
