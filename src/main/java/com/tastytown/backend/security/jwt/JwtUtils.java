package com.tastytown.backend.security.jwt;

import java.util.Base64;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
    private static final String JWT_SECRET = 
                            "bce0b4720748f6c84049ff571c9253d518bba268fe159d432d8732d2f4186c88";

    private SecretKey getKey() {
        byte[] keyBytes = Base64.getDecoder().decode(JWT_SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String userId, String role) {
        return Jwts.builder()
                .subject(userId)
                .claim("role", role)
                .signWith(getKey())
                .compact();
    }

    public String getUserId(String token) { // verifyToken, verify, claimUsername
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String getUserRole(String token) { // verifyToken, verify, claimUsername
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role")
                .toString();
    }
}
