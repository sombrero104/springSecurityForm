package sombrero.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * 메소드 시큐리티.
 * 세가지의 애노테이션 사용 가능.
 * 아래처럼 설정해줘야 각각의 애노테이션 사용 가능.
 * @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
 * (1) securedEnabled: @Secured 활성화.
 * (2) prePostEnabled: @PreAuthorized, @PostAuthorized 활성화.
 * (3) jsr250Enabled: @RolesAllowed 활성화.
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
public class MethodSecurity {
}
