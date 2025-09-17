package com.example.demo.user;

import com.example.demo.security.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final SessionService sessions;

    public JwtAuthFilter(JwtService jwtService, SessionService sessions) {
        this.jwtService = jwtService;
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        String path = req.getRequestURI();
        if (path.startsWith("/api/auth/")) {
            chain.doFilter(req, res);
            return;
        }

        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            unauthorized(res, "auth.missing");
            return;
        }
        String token = header.substring(7).trim();

        try {
            // Verify JWT signature/exp
            JwtPrincipal p = jwtService.verify(token);
            // Idle timeout check via Redis (sliding)
            String jti = jwtService.extractJti(token);
            if (!sessions.touch(jti)) {
                unauthorized(res, "auth.expired");
                return;
            }

            var auth = new UsernamePasswordAuthenticationToken(p, null, List.of(new SimpleGrantedAuthority("ROLE_" + p.role())));
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(req, res);
        } catch (SecurityException se) {
            unauthorized(res, switch (se.getMessage()) {
                case "expired" -> "auth.expired";
                case "invalid-signature" -> "auth.invalidsig";
                default -> "auth.invalid";
            });
        } catch (Exception e) {
            unauthorized(res, "auth.invalid");
        }
    }

    private void unauthorized(HttpServletResponse res, String msg) throws IOException {
        res.setStatus(401);
        res.setContentType("application/json");
        res.getWriter().write("{\"error\":\"" + msg + "\"}");
    }
}
