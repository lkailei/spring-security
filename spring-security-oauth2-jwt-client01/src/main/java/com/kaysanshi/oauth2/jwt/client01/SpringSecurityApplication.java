package com.kaysanshi.oauth2.jwt.client01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

/**
 * 对应的是spring-security-oauth2-jwt-server服务注册的客户端
 * 将两个客服端服务都去server认证
 */
@SpringBootApplication
// 开启单点登录
@EnableOAuth2Sso
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

}
