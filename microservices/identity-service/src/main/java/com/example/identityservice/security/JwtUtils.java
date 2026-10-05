package com.example.identityservice.security;

import com.example.identityservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Access Token = JWT ngắn hạn, tự chứa thông tin (stateless) -> service khác tự kiểm chữ ký, không cần gọi DB.
 * Header: {"alg":"HS256"} | Payload: jti, sub, roles, iat, exp | Signature: HMAC-SHA256(secret)
 */
@Component
public class JwtUtils {

    public static final String ROLES_CLAIM = "roles";

    private final Key signingKey;
    private final long accessTokenExpirationMs;

    public JwtUtils(@Value("${app.jwt.secret}") String secret,
                    @Value("${app.jwt.access-token-expiration}") long accessTokenExpirationMs) {
        // hmacShaKeyFor ném WeakKeyException nếu khóa < 256 bit
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
    }

    public String generateAccessToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpirationMs);

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())                    // jti: ID duy nhất của token
                .setSubject(user.getUsername())                         // sub
                .claim(ROLES_CLAIM, List.of(user.getRole().name()))     // roles: ["USER"]
                .setIssuedAt(now)                                       // iat
                .setExpiration(expiry)                                  // exp (15 phút)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /** Xác minh chữ ký + hạn dùng. Ném JwtException nếu token không hợp lệ hoặc hết hạn. */
    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public long getAccessTokenExpirationMs() {
        return accessTokenExpirationMs;
    }
}
