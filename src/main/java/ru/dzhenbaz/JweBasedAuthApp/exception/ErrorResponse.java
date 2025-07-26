package ru.dzhenbaz.JweBasedAuthApp.exception;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ErrorResponse {

    @Schema(description = "HTTP код ошибки", example = "401")
    private final int status;

    @Schema(description = "Сообщение об ошибке", example = "Invalid or expired token")
    private final String error;

    @Schema(description = "URI, вызвавший ошибку", example = "/api/secure")
    private final String path;

    public ErrorResponse(HttpStatus status, String message, String path) {
        this.status = status.value();
        this.error = message;
        this.path = path;
    }
}
