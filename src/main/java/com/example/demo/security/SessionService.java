package com.example.demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class SessionService {
    private final StringRedisTemplate redis;
    private final Duration idleTtl;

    public SessionService(StringRedisTemplate redis,
                          @Value("${app.session.idleSeconds:600}") long idleSeconds) {
        this.redis = redis;
        this.idleTtl = Duration.ofSeconds(idleSeconds);
    }

    private String key(String jti) {
        return "sess:" + jti;
    }

    /**
     * Called at login
     */
    public void start(String jti, String userId) {
        redis.opsForValue().set(key(jti), userId, idleTtl);
    }

    /**
     * Called on every authenticated request
     */
    public boolean touch(String jti) {
        var k = key(jti);
        Boolean exists = redis.hasKey(k);
        if (exists != null && exists) {
            redis.expire(k, idleTtl); // refresh TTL -> sliding/idle expiration
            return true;
        }
        return false;
    }

    /**
     * Optional: logout/revoke
     */
    public void end(String jti) {
        redis.delete(key(jti));
    }
}
