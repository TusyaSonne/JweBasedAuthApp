package ru.dzhenbaz.JweBasedAuthApp.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Запрос на регистрацию или логин")
public record AuthRequest(
        @Schema(description = "Имя пользователя", example = "john")
        String username,
        @Schema(description = "Пароль", example = "1234")
        String password) {
}
