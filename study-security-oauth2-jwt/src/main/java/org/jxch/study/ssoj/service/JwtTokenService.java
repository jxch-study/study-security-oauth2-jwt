package org.jxch.study.ssoj.service;

import com.alibaba.fastjson2.JSON;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.jxch.study.ssoj.entity.dto.TokenSubject;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class JwtTokenService {
    public static final long EXPIRATION_TIME = 3_600_000;
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public Date getExpiration(long expirationTime) {
        return new Date(new Date().getTime() + expirationTime);
    }

    public String createToken(TokenSubject subject, Date expiration) {
        return Jwts.builder()
                .setSubject(JSON.toJSONString(subject))
                .signWith(key)
                .setExpiration(expiration)
                .compact();

    }

    public String createDefaultToken(TokenSubject subject) {
        return createToken(subject, getExpiration(EXPIRATION_TIME));
    }

    public boolean validateToken(String token) {
        return Objects.nonNull(parseToken(token));
    }

    public TokenSubject parseToken(String token) {
        try {
            return JSON.parseObject(Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject(), TokenSubject.class);
        } catch (Exception e) {
            return null;
        }
    }

}
