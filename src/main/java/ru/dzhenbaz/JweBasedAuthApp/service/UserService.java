package ru.dzhenbaz.JweBasedAuthApp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.dzhenbaz.JweBasedAuthApp.model.User;
import ru.dzhenbaz.JweBasedAuthApp.repository.UserRepository;

import java.util.UUID;

/**
 * Сервис для управления пользователями и логикой аутентификации.
 * <p>
 * Отвечает за регистрацию новых пользователей и проверку логина/пароля при аутентификации.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Регистрирует нового пользователя.
     * <ul>
     *     <li>Проверяет уникальность имени</li>
     *     <li>Хэширует пароль</li>
     *     <li>Генерирует чувствительный секретный код</li>
     *     <li>Сохраняет пользователя в БД</li>
     * </ul>
     *
     * @param username    имя пользователя
     * @param rawPassword пароль в открытом виде
     * @throws RuntimeException если пользователь с таким именем уже существует
     */
    public void register(String username, String rawPassword) {
        if (userRepository.existsByUsername(username)) throw new RuntimeException("Already exists");

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));

        // Имитация чувствительного кода
        String generatedSecret = UUID.randomUUID().toString();
        user.setSecretCode(generatedSecret);

        userRepository.save(user);
    }

    /**
     * Аутентифицирует пользователя по имени и паролю.
     *
     * @param username имя пользователя
     * @param password пароль в открытом виде
     * @return объект пользователя при успешной проверке
     * @throws RuntimeException если пользователь не найден или пароль неверный
     */
    public User authenticate(String username, String password) {
        User user = userRepository.findByUsername(username).orElseThrow();
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Bad credentials");
        }
        return user;
    }
}
