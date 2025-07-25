package ru.dzhenbaz.JweBasedAuthApp.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class ErrorResponse {
    private final int status;
    private final String error;
    private final String path;

    public ErrorResponse(HttpStatus status, String message, String path) {
        this.status = status.value();
        this.error = message;
        this.path = path;
    }
}
