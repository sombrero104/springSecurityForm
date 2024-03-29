package sombrero.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import sombrero.account.AccountService;
import sombrero.common.LoggingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 50)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

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
    public void configure(WebSecurity web) throws Exception {

        /**
         * static 리소스에 대해 ignoring()
         * static 리소스 요청에 대해 필터를 처리하지 않아도 되므로 필터 목록 수 0개가 됨.
         * (configure(HttpSecurity http)에 permitAll() 설정을 해도 결과는 같지만 필터를 다 타게 되어서 좋지 않음.
         *  필터를 타야 하는 경우(동적 리소스)에는 configure(HttpSecurity http) 사용.)
         */
        // web.ignoring().mvcMatchers("/favicon.ico");
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 커스텀 Filter 만들기. 설정 추가.
         */
        // http.addFilterAfter() // 특정 Filter 뒤에 커스텀 Filter를 추가할 경우.
        // http.addFilterBefore() // 특정 Filter 앞에 커스텀 Filter를 추가할 경우.
        // http.addFilterAt() // 특정 Filter 위치에 커스텀 Filter를 추가할 경우.
        http.addFilterBefore(new LoggingFilter(), WebAsyncManagerIntegrationFilter.class);
        // 1번 필터인 WebAsyncManagerIntegrationFilter 필터 앞에 진행.
        // LoggingFilter에서 추가한 성능측정(로그인 시 얼마나 걸렸는지)이 모든 필터가 진행되는 끝까지 측정됨.

        http.authorizeRequests()
                // .antMatchers("/").permitAll()
                // .regexMatchers("/").permitAll()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                // .mvcMatchers("/user").hasAuthority("ROLE_USER") // hasAuthority() 사용할 경우 'ROLE_' 붙여줘야 함.
                .mvcMatchers("/user").hasRole("USER")
                // .anyRequest().anonymous() // 익명 사용자에게만 허용할 경우.
                // .anyRequest().not().anonymous() // 익명 사용자가 아닌 경우 다 허용.
                // .anyRequest().rememberMe() // Remember me 기능으로 인증을 한 사용자의 경우 접근 허용.
                // .anyRequest().fullyAuthenticated() // Remember me로 인증이 된 사용자의 경우 중요한 url에서는 다시 로그인을 요구.
                                                    // (예, 장바구니 히스토리를 보거나 주문할 때. 그전까지는 Remember me로 동작을 하다가 중요한 url에서 다시 로그인을 요구.)
                // .anyRequest().denyAll() // 아무것도 허용하지 경우.
                .anyRequest().authenticated() // 인증이 되기만 하면 접근 허용.
                // .accessDecisionManager(accessDecisionManager()) // 1. AccessDecisionManager를 커스터마이징하는 방법.
                .expressionHandler(securityExpressionHandler()); // 2. SecurityExpressionHandler를 커스터마이징하는 방법.
        // http.formLogin();
        /*http.formLogin()
                .usernameParameter("my-username")
                .passwordParameter("my-password");*/ // form 로그인페이지 파라미터 변경. 자동으로 생성되는 login페이지도 자동으로 바뀜.
        /**
         * 커스텀한 로그인페이지를 만들 경우.
         * DefaultLoginPageGeneratingFilter와 DefaultLogoutPageGeneratingFilter를 타지 않음. 직접 만들어야함.
         * GET 요청일 경우에는 form 로그인 페이지를, POST 요청일 경우에는 UsernamePasswordAuthenticationFitler 처리를 탐.
         * GET 요청일 경우에 보여주는 form 로그인 페이지만 커스텀.
         */
        http.formLogin().loginPage("/login").permitAll();

        http.rememberMe()
                // .rememberMeParameter("remember") // 로그인 페이지에서도 파라미터를 remember로 바꿔줘야 함. 기본값은 remember-me.
                // .tokenValiditySeconds() // 쿠키를 유지하는 시간을 변경할 때 사용. 기본값은 2주.
                // .useSecureCookie(true) // HTTS만 이 쿠키에 접근 가능하도록 함.
                // .alwaysRemember(true) // 로그인 페이지 form에서 파라미터를 넣어주지 않더라도 기본적으로 RememberMe 기능 사용하도록 함. 기본값은 false.
                .userDetailsService(accountService)
                .key("remember-me");

        http.httpBasic();
        // 필터 15개

        // 403에러. Access denied 커스텀 페이지. (인증은 되어 있는데 해당 리소스에 대해 권한이 충분하지 않은 경우.)
        // http.exceptionHandling().accessDeniedPage("/access-denied");
        // 로그를 남기고 싶을 경우.(어느 곳에 비정상적인 접근을 하였는지 ) AccessDeniedHandler 구현하면 됨.
        // 아래와 다르게 AccessDeniedHandler를 별도의 클래스로 만드는 것을 권장.
        http.exceptionHandling()
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                        UserDetails principal = (UserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                        String username = principal.getUsername();
                        System.out.println(username + " is denied to access " + request.getRequestURI());
                        // 결과: sombrero is denied to access /admin
                        response.sendRedirect("/access-denied");
                    }
                });

        /**
         * SecurityContextHolder의 전략 설정 변경.
         *
         * MODE_INHERITABLETHREADLOCAL
         *  => 현재 스레드내에서 하위 스레드를 생성할 경우, SecurityContextHolder 공유가 가능하도록 설정.
         */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        /**
         * 로그아웃 커스텀
         */
        http.logout()
                .logoutUrl("/logout") // 로그아웃 할 수 있는 페이지. 다른 경로로 로그아웃 페이지를 커스텀할 수 있음.
                .logoutSuccessUrl("/"); // 로그아웃 후 이동할 페이지.
                // .deleteCookies("쿠키 이름") // 로그아웃 할 때 쿠키 삭제.
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

    /**
     * AuthenticationManager을 빈으로 등록.
     * SampleServiceTest.java에서 코드로 인증할 때 사용.
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
