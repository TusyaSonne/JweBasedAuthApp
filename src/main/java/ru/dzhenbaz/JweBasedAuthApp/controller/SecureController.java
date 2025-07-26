package ru.dzhenbaz.JweBasedAuthApp.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.TokenPayload;

/**
 * Контроллер, обрабатывающий доступ к защищённому ресурсу.
 * <p>
 * Требует JWE-токен в заголовке Authorization и возвращает зашифрованные пользовательские данные,
 * извлечённые из токена.
 */
@RestController
@RequestMapping("/api/secure")
@Tag(name = "Проверка доступа", description = "Эндпоинт, требующий JWE")
public class SecureController {

    /**
     * Обрабатывает запрос к защищённому ресурсу.
     * <p>
     * Извлекает {@link TokenPayload} из JWE-токена, полученного ранее и помещённого
     * в {@link org.springframework.security.core.Authentication#getPrincipal()} фильтром.
     *
     * @param authentication объект, содержащий расшифрованные данные из токена
     * @return сообщение с именем пользователя и его чувствительным кодом
     */
    @Operation(
            summary = "Получить защищённые данные",
            description = "Возвращает расшифрованные в токене данные"
    )
    @GetMapping
    public ResponseEntity<String> getSecureData(Authentication authentication) {
        TokenPayload payload = (TokenPayload) authentication.getPrincipal();
        String username = payload.getUsername();
        String secretCode = payload.getSecretCode();

        return ResponseEntity.ok("Hello " + username + ", your secret code, that nobody will know: " + secretCode);
    }
}
