package com.example.demo.user;

import com.example.demo.security.SessionService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final SessionService sessions;

    public AuthController(UserRepository repo, PasswordEncoder encoder, JwtService jwt, SessionService sessions) {
        this.repo = repo;
        this.encoder = encoder;
        this.jwt = jwt;
        this.sessions = sessions;
    }

    // REGISTER
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest req) {
        if (repo.existsByEmail(req.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "email already exists");
        }
        String hash = encoder.encode(req.password());
        User u = repo.save(new User(req.name(), req.email(), hash));
        return new RegisterResponse(u.getId());
    }

    // LOGIN
    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req) throws Exception {
        var u = repo.findByNameOrEmail(req.identifier(), req.identifier())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid credentials"));
        if (!encoder.matches(req.password(), u.getPasswordHash()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid credentials");

        String token = jwt.sign(String.valueOf(u.getId()), u.getName(), u.getEmail(), u.getRole());
        // start sliding session keyed by JTI
        String jti = jwt.extractJti(token);
        sessions.start(jti, String.valueOf(u.getId()));

        return new LoginResponse(token);
    }

}