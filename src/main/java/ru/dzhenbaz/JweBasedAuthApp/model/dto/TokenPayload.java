package ru.dzhenbaz.JweBasedAuthApp.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO, представляющий полезную нагрузку JWE-токена.
 * <p>
 * Содержит данные, которые шифруются и передаются внутри токена:
 * имя пользователя и чувствительный код.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TokenPayload {

    /**
     * Имя пользователя (уникальный идентификатор пользователя в системе).
     */
    private String username;

    /**
     * Чувствительные данные, связанные с пользователем (например, персональный код).
     */
    private String secretCode; // Чувствительные данные
}

