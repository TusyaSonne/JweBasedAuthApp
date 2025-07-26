package ru.dzhenbaz.JweBasedAuthApp.model.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Ответ с JWE-токеном")
public record AuthResponse(String token) {
}
