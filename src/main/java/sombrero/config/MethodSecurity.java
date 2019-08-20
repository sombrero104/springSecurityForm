package sombrero.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * 메소드 시큐리티.
 * 세가지의 애노테이션 사용 가능.
 * 아래처럼 설정해줘야 각각의 애노테이션 사용 가능.
 * @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
 * (1) securedEnabled: @Secured 활성화.
 *      => 메소드 호출 이전에 권한을 확인한다. 스프링 EL을 사용하지 못한다.
 * (2) prePostEnabled: @PreAuthorized, @PostAuthorized 활성화.
 *      => 메소드 호출 이전 이후에 권한을 확인할 수 있다.
 *         스프링 EL을 사용하여 메소드 매개변수와 리턴값을 검증할 수도 있다.
 * (3) jsr250Enabled: @RolesAllowed 활성화.
 *      => 메소드 호출 이전에 권한을 확인한다. 스프링 EL을 사용하지 못한다.
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
public class MethodSecurity {
}
