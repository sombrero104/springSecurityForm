package sombrero.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import sombrero.account.AccountService;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 50)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /*@Autowired
    AccountService accountService;*/

    /**
     * 권한 커스터마이징 방법
     *
     * 1. AccessDecisionManager를 커스터마이징하는 방법.
     * 디폴트 AccessDecisionManager인 AffirmativeBased를 사용하지 않고 커스텀할 경우.
     * (ROLE_ADMIN을 ROLE_USER의 상위 권한으로 지정하고 싶을 경우. ADMIN 권한의 사용자가 USER 권한의 페이지에 접근 가능하도록 할 경우.)
     */
    public AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);

        List<AccessDecisionVoter<? extends Object>> voters = Arrays.asList(webExpressionVoter);
        AccessDecisionManager accessDecisionManager = new AffirmativeBased(voters);
        return accessDecisionManager;
    }

    /**
     * 2. SecurityExpressionHandler를 커스터마이징하는 방법.
     */
    public SecurityExpressionHandler securityExpressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                // .accessDecisionManager(accessDecisionManager()) // 1. AccessDecisionManager를 커스터마이징하는 방법.
                .expressionHandler(securityExpressionHandler()); // 2. SecurityExpressionHandler를 커스터마이징하는 방법.
        http.formLogin();
        http.httpBasic();
        // 필터 15개
    }

    /**
     * Spring security에서 기본으로 만들어주는 인메모리 user의 패스워드는
     * SecurityProperties에서 생성한 것을 받아서 UserDetailsServiceAutoConfiguration가 출력해 줌.
     * application.properties에 설정하면 출력하지 않음.
     */

    /**
     * {noop} : 기본 패스워드 인코더가 사용할 암호화 방식을 정의하는 prefix.
     *          form에서 입력한 패스워드를 이 prefix의 암호화 방식으로 암호화하여 비교함.
     *          'noop'은 암호화를 하지 않았다는 뜻.
     */
    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sombrero").password("{noop}123").roles("USER").and()
                .withUser("admin").password("{noop}123").roles("ADMIN");
    }*/

    /**
     * AuthenticationManagerBuilder에게 사용할 UserDetailsService를 알려줄 때
     * 아래처럼 정의하지 않아도 UserDetailsService를 구현한 AccountService가 빈으로 등록되어 있으면 자동으로 사용하게 됨.
     */
    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService);
    }*/
}
