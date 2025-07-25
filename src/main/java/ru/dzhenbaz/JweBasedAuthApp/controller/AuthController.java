package ru.dzhenbaz.JweBasedAuthApp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.dzhenbaz.JweBasedAuthApp.model.User;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.AuthRequest;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.AuthResponse;
import ru.dzhenbaz.JweBasedAuthApp.service.JweTokenService;
import ru.dzhenbaz.JweBasedAuthApp.service.UserService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {


    private final UserService userService;
    private final JweTokenService jweTokenService;

    public AuthController(UserService userService, JweTokenService jweTokenService) {
        this.userService = userService;
        this.jweTokenService = jweTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        userService.register(request.username(), request.password());
        return ResponseEntity.ok("Registered");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) throws Exception {
        User user = userService.authenticate(request.username(), request.password());
        String token = jweTokenService.generateToken(user.getUsername());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
