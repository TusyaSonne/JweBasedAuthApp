package ru.dzhenbaz.JweBasedAuthApp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.TokenPayload;

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping
    public ResponseEntity<String> getSecureData(Authentication authentication) {
        TokenPayload payload = (TokenPayload) authentication.getPrincipal();
        String username = payload.getUsername();
        String secretCode = payload.getSecretCode();

        return ResponseEntity.ok("Hello " + username + ", your secret code, that nobody will know: " + secretCode);
    }
}
