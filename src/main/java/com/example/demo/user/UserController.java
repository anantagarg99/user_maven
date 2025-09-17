package com.example.demo.user;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import jakarta.validation.Valid;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository repo;

    public UserController(UserRepository repo) {
        this.repo = repo;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    // in UserController.java, if you want to keep a "create" separate from register:
    public User create(@Valid @RequestBody CreateUserRequest req, PasswordEncoder encoder) {
        if (repo.existsByEmail(req.email()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "email already exists");
        return repo.save(new User(req.name(), req.email(), encoder.encode("default-password")));
    }

    @GetMapping("/by-email")
    @PreAuthorize("#email?.toLowerCase() == authentication.principal.email?.toLowerCase() or hasRole('ADMIN')")
    public User byEmail(@RequestParam String email) {
        return repo.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found"));
    }

    // ADMIN can list all
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> list() {
        return repo.findAll();
    }

    // SELF or ADMIN can read one
    @GetMapping("/{id}")
    @PreAuthorize("#id.toString() == authentication.principal.userId or hasRole('ADMIN')")
    public User get(@PathVariable Long id) {
        return repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found"));
    }

    // SELF or ADMIN can update
    @PutMapping("/{id}")
    @PreAuthorize("#id.toString() == authentication.principal.userId or hasRole('ADMIN')")
    public User update(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest req) {
        User u = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found"));
        if (!u.getEmail().equals(req.email()) && repo.existsByEmail(req.email())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "email already exists");
        }
        u.setName(req.name());
        u.setEmail(req.email());
        return repo.save(u);
    }

    // SELF or ADMIN can delete
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("#id.toString() == authentication.principal.userId or hasRole('ADMIN')")
    public void delete(@PathVariable Long id) {
        if (!repo.existsById(id)) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found");
        repo.deleteById(id);
    }
}
