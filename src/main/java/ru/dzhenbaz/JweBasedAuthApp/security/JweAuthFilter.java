package ru.dzhenbaz.JweBasedAuthApp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.dzhenbaz.JweBasedAuthApp.exception.ErrorResponse;
import ru.dzhenbaz.JweBasedAuthApp.model.dto.TokenPayload;
import ru.dzhenbaz.JweBasedAuthApp.service.JweTokenService;

import java.io.IOException;
import java.util.List;

/**
 * Фильтр авторизации на основе JWE-токена.
 * <p>
 * Извлекает токен из заголовка Authorization, расшифровывает его, проверяет корректность
 * и устанавливает пользователя в контекст безопасности {@link SecurityContextHolder}.
 * <p>
 * Пропускает публичные маршруты, указанные в {@code PUBLIC_URLS}.
 */
@RequiredArgsConstructor
public class JweAuthFilter extends OncePerRequestFilter {

    /**
     * Сервис для расшифровки JWE-токенов.
     */
    private final JweTokenService tokenService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Список публичных URL, для которых фильтр не применяется.
     */
    private static final List<String> PUBLIC_URLS = List.of(
            "/api/auth/login",
            "/api/auth/register"
    );

    /**
     * Основной метод фильтра. Проверяет наличие Bearer-токена в заголовке запроса, валидирует его
     * и помещает объект {@link TokenPayload} в контекст Spring Security.
     *
     * @param request     входящий HTTP-запрос
     * @param response    HTTP-ответ
     * @param filterChain цепочка последующих фильтров
     * @throws ServletException в случае ошибки фильтрации
     * @throws IOException      в случае ошибки ввода-вывода
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                String payload = tokenService.decryptToken(token);

                TokenPayload tokenPayload = objectMapper.readValue(payload, TokenPayload.class);

                Authentication auth = new UsernamePasswordAuthenticationToken(tokenPayload, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                ErrorResponse error = new ErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid token",
                        request.getRequestURI()
                );

                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType("application/json");
                response.getWriter().write(new ObjectMapper().writeValueAsString(error));
                return;
            }
        }

        filterChain.doFilter(request, response);

    }

    /**
     * Определяет, должен ли фильтр применяться к текущему запросу.
     * <p>
     * Возвращает {@code true}, если путь начинается с одного из публичных URL.
     *
     * @param request текущий HTTP-запрос
     * @return {@code true}, если фильтр следует пропустить
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return PUBLIC_URLS.stream().anyMatch(path::startsWith);
    }
}
