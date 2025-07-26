package ru.dzhenbaz.JweBasedAuthApp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Конфигурация генерации RSA-ключей для JWE.
 * <p>
 * Генерирует пару ключей (публичный и приватный) при запуске приложения и
 * предоставляет их как Spring-бин.
 * <p>
 * Эти ключи используются для шифрования и расшифровки JWE-токенов.
 */
@Configuration
public class RsaKeyConfig {

    /**
     * Сгенерированная пара RSA-ключей (2048 бит).
     */
    private final KeyPair keyPair;

    /**
     * Конструктор. Генерирует RSA-ключи при инициализации конфигурации.
     *
     * @throws RuntimeException если алгоритм RSA не поддерживается
     */
    public RsaKeyConfig() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Возвращает сгенерированную пару RSA-ключей.
     *
     * @return {@link KeyPair}, содержащий приватный и публичный ключ
     */
    @Bean
    public KeyPair keyPair() {
        return this.keyPair;
    }
}
