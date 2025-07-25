package ru.dzhenbaz.JweBasedAuthApp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.dzhenbaz.JweBasedAuthApp.model.User;
import ru.dzhenbaz.JweBasedAuthApp.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void register(String username, String rawPassword) {
        if (userRepository.existsByUsername(username)) throw new RuntimeException("Already exists");
        userRepository.save(new User(username, passwordEncoder.encode(rawPassword)));
    }

    public User authenticate(String username, String password) {
        User user = userRepository.findByUsername(username).orElseThrow();
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Bad credentials");
        }
        return user;
    }
}
