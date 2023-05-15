package org.jxch.study.ssoj.service;

import com.alibaba.fastjson2.JSON;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.jxch.study.ssoj.entity.dto.TokenSubject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@Slf4j
@SpringBootTest
class JwtTokenServiceTest {
    @Autowired
    public JwtTokenService jwtTokenService;

    @Test
    public void token() {
        String token = jwtTokenService.createDefaultToken(new TokenSubject("userid", "passwd"));
        log.info(token);
        TokenSubject tokenSubject = jwtTokenService.parseToken(token);
        log.info(JSON.toJSONString(tokenSubject));
    }

}