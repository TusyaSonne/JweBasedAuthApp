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
import ru.dzhenbaz.JweBasedAuthApp.model.dto.TokenPayload;
import ru.dzhenbaz.JweBasedAuthApp.service.JweTokenService;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JweAuthFilter extends OncePerRequestFilter {

    private final JweTokenService tokenService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                String payload = tokenService.decryptToken(token);

                TokenPayload tokenPayload = objectMapper.readValue(payload, TokenPayload.class);
                String username = tokenPayload.getSub();

                Authentication auth = new UsernamePasswordAuthenticationToken(username, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }
        }

        filterChain.doFilter(request, response);

    }
}
