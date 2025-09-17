package com.example.demo.user;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private final byte[] secret;
    private final String issuer;
    private final long ttlSec;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.issuer}") String issuer,
                      @Value("${app.jwt.ttlSeconds}") long ttlSec) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.issuer = issuer;
        this.ttlSec = ttlSec;
    }

    /**
     * Create a signed HS256 JWT. subject = userId
     */
    public String sign(String subject, String name, String email, String role) throws JOSEException {
        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .subject(subject)
                .issuer(issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(ttlSec))) // absolute expiry (e.g., 15m)
                .claim("name", name)
                .claim("email", email)
                .claim("role", role)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    /**
     * Verify signature/expiry and return principal.
     */
    public JwtPrincipal verify(String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);
        if (!jwt.verify(new MACVerifier(secret))) throw new SecurityException("invalid-signature");
        var c = jwt.getJWTClaimsSet();
        var exp = c.getExpirationTime();
        if (exp == null || exp.before(new Date())) throw new SecurityException("expired");
        return new JwtPrincipal(c.getSubject(), c.getStringClaim("name"), c.getStringClaim("email"),
                c.getStringClaim("role"));
    }

    public String extractJti(String token) throws Exception {
        return SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
    }
}
