package ru.dzhenbaz.JweBasedAuthApp.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Конфигурация Swagger/OpenAPI 3.0 для генерации интерактивной документации REST API.
 * <p>
 * Добавляет метаинформацию о сервисе и конфигурацию безопасности на основе Bearer-токена (JWE).
 */
@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI apiInfo() {

        final String securitySchemeName = "BearerAuth";

        return new OpenAPI()
                .info(new Info()
                        .title("JWE-based authorization Service")
                        .version("1.0")
                        .description("Сервис авторизации при помощи JWE-токенов с защитой тела токена от компроментации и подмены")
                        .contact(new Contact()
                                .name("Dzhenbaz Arthur")
                                .email("artur.dzhenbaz@gmail.com")
                                .url("https://github.com/TusyaSonne")))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components().addSecuritySchemes(securitySchemeName,
                        new SecurityScheme()
                                .name(securitySchemeName)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .in(SecurityScheme.In.HEADER)
                ));
    }
}
