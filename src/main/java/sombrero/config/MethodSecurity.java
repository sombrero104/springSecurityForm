package sombrero.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

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
/**
 * 메소드 시큐리티에서
 * "ROLE_ADMIN > ROLE_USER" Hierarchy(ADMIN은 USER 권한도 가진다.)를
 * 인식하도록 하려면 GlobalMethodSecurityConfiguration를 상속받아서 accessDecisionManager()를 오버라이딩하여
 * RoleHierarchyImpl를 만들어서 AccessDecisionManager에 새 RoleHierarchyVoter를 추가하여 넣어줌.
 * 테스트: 테스트 코드인 SampleServiceTest.java에서 ADMIN 권한으로 인증하여 USER권한 메소드인 dashboard()에 접근.
 * (@Secured("ROLE_USER") 와 @RolesAllowed("ROLE_USER")은 사용이 되는데 @PreAuthorize("hasRole('USER')") 는 안됨.)
 */
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)
public class MethodSecurity extends GlobalMethodSecurityConfiguration {

    @Override
    protected AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        /**
         * AccessDecisionManager를 상위 클래스에서 받아와서 커스터마이징.
         */
        // AccessDecisionManager accessDecisionManager = super.accessDecisionManager();
        AffirmativeBased accessDecisionManager = (AffirmativeBased)super.accessDecisionManager();
        accessDecisionManager.getDecisionVoters().add(new RoleHierarchyVoter(roleHierarchy));
        return accessDecisionManager;
    }

}
