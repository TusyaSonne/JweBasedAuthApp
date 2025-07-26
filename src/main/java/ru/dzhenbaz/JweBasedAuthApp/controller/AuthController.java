package ru.dzhenbaz.JweBasedAuthApp.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
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

/**
 * Контроллер, обрабатывающий действия, связанные с аутентификацией пользователей:
 * регистрацию и логин.
 * <p>
 * Возвращает JWE-токен при успешной аутентификации.
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Аутентификация", description = "Регистрация и вход пользователя")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JweTokenService jweTokenService;

    /**
     * Регистрирует нового пользователя.
     *
     * @param request объект запроса с именем пользователя и паролем
     * @return сообщение об успешной регистрации
     */
    @Operation(
            summary = "Регистрация нового пользователя",
            description = "Создаёт пользователя"
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        userService.register(request.username(), request.password());
        return ResponseEntity.ok("Registered");
    }

    /**
     * Аутентифицирует пользователя и возвращает JWE-токен.
     *
     * @param request объект запроса с именем пользователя и паролем
     * @return объект {@link AuthResponse} с токеном
     * @throws Exception в случае ошибок генерации токена
     */
    @Operation(
            summary = "Вход пользователя",
            description = "Проверяет логин и пароль, возвращает JWE-токен"
    )
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) throws Exception {
        User user = userService.authenticate(request.username(), request.password());
        String token = jweTokenService.generateToken(user);
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
