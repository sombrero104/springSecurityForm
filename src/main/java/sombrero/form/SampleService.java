package sombrero.form;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import sombrero.account.Account;
import sombrero.account.AccountContext;
import sombrero.common.SecurityLogger;

import javax.annotation.security.RolesAllowed;
import java.util.Collection;

@Service
public class SampleService {

    /**
     * Spring Security의 구조.
     *
     * Authentication(인증)
     * DelegatingFilterProxy
     *  -> FilterChainProxy
     *  -> SecurityContextPersistenceFilter, UsernamePasswordAuthenticationFilter
     *  -> SecurityContextHolder -> SecurityContext -> AuthenticationManager -> Authentication
     *
     * 1. SecurityContextHolder
     *  -> SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다. (하나의 스레드에서 자원 공간을 공유하 방식.)
     *                          한 스레드에 특화되어 있는 정보. 한 스레드 내에서는 어디에서나 접근 가능. 스레드가 다를 경우 같은 인증 정보를 가져올 수 없음.
     *                          ThreadLocal 외에 다른 전략 사용 필요.
     *                          async하게 threadpool을 사용하지 않는 이상 서블릿은 thread per request(스레드 하나 = 요청 하나)이므로 기본적으로 ThreadLocal 사용.
     * 2. SecurityContext
     *  -> Authentication 제공.
     */
    // @Secured("ROLE_USER")
    // @RolesAllowed("ROLE_USER")
    @PreAuthorize("hasRole('USER')")
    public void dashboard() {

        /**
         * 3. authentication: Principal과 GrantAuthority 제공.
         *
         * 디버깅 결과:
         * org.springframework.security.authentication.UsernamePasswordAuthenticationToken@e27597c5: Principal:
         * org.springframework.security.core.userdetails.User@59957021:
         *  Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true;
         *  AccountNonLocked: true; Granted Authorities: ROLE_USER; Credentials: [PROTECTED]; Authenticated: true;
         *  Details: org.springframework.security.web.authentication.WebAuthenticationDetails@fffde5d4: RemoteIpAddress: 0:0:0:0:0:0:0:1;
         *  SessionId: 1AB7F5F9088D4DAAA552FF9618328D23; Granted Authorities: ROLE_USER
         */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        /**
         * 4. principal: 인증한 사용자를 나타내는 정보.
         *            UserDetailsService에서 리턴한 UserDetails 타입의 객체.
         *
         *            * UserDetails: 애플리케이션이 가지고 있는 유저 정보와 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.
         *            * UserDetailsService: 유저 정보를 UserDetails 타입으로 가져오는 DAO(Data Access Object) 인터페이스.
         *                                  유저 정보를 스프링 시큐리티(Authentication Manager)에 제공하여 인증하도록 하는 역할.
         *
         * 디버깅 결과:
         * org.springframework.security.core.userdetails.User@59957021:
         *  Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true;
         *  AccountNonLocked: true; Granted Authorities: ROLE_USER
         */
        // Object principal = authentication.getPrincipal();
        UserDetails userDetails = (UserDetails)authentication.getPrincipal();

        /**
         * 5. authorities(GrantedAuthority): "ROLE_USER", "ROLE_ADMIN" 등 사용자가 가지고 있는 권한.
         *                                인증 이후, 인가 및 권한을 확인할 때 이 정보를 참조한다.
         *                                사용자가 가지고 있는 권한이 여러개일 수도 있으므로 컬렉션 타입.
         *
         * 디버깅 결과:
         *  authorities = {Collections$UnmodifiableRandomAccessList@11097}  size = 1
         *  0 = {SimpleGrantedAuthority@11104} "ROLE_USER"
         *  role = "ROLE_USER"
         */
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        /**
         * 6. credentials: 인증할 때만 사용. (인증을 한 다음에는 값을 가지고 있을 필요가 없기 때문에 현재는 값이 없음.)
         *
         * 디버깅 결과:
         * credentials = null
         */
        Object credentials = authentication.getCredentials();

        /**
         * 7. authenticated: 인증된 사용자인지 나타내는 정보.
         *
         * 디버깅 결과:
         * authenticated = true
         */
        boolean authenticated = authentication.isAuthenticated();

    }

    /**
     * ThreadLocal 사용해보기.
     * 커스텀 AccountContext에 ThreadLocal로 저장한 Account 정보 가져오기.
     * (SecurityContextHolder의 기본 전략이 ThreadLocal.)
     */
    public void dashboard2() {
        Account account = AccountContext.getAccount();
        System.out.println("================================");
        System.out.println(account.getUsername());
        System.out.println("================================");
    }

    /**
     * @Async
     * 별도의 스레드를 만들어서 비동기적으로 호출해줌.
     * @Async 애노테이션만 붙이면 다른 스레드로 동작하지 않음. (그냥 같은 스레드로 동작.)
     *  => 스프링부트 실행 Application에 @EnableAsync를 붙여야 제대로 다른 스레드로 동작함. (기본적인 스레드풀보다 다른 스레드풀 설정 권장.)
     *
     * SecurityContextHolder의 기본 전략이 ThreadLocal이기 때문에
     * 기본적으로 @Async를 사용하는 곳에서는 SecurityContextHolder 공유가 안됨. (인증된 사용자 정보를 사용할 수 없음.)
     *  => SecurityContextHolder의 전략을 바꾸는 설정 필요.
     *  => SecurityConfig의 configure(HttpSecurity http)에 아래 설정 추가.
     *      SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
     *
     * 실행 결과:
     * ---------------------------------------------------
     * # MVC, before async service
     * # thread.getName(): http-nio-8080-exec-2
     * # principal: org.springframework.security.core.userdetails.User@59957021: Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
     * ---------------------------------------------------
     * ---------------------------------------------------
     * # MVC, after async service
     * # thread.getName(): http-nio-8080-exec-2
     * # principal: org.springframework.security.core.userdetails.User@59957021: Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
     * ---------------------------------------------------
     * ---------------------------------------------------
     * # Async service is called.
     * # thread.getName(): task-1
     * # principal: org.springframework.security.core.userdetails.User@59957021: Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
     * ---------------------------------------------------
     *
     *  => 동일한 Principal을 참조하고 있는 것을 확인할 수 있음.
     */
    @Async
    public void asyncService() {
        SecurityLogger.log("Async service is called.");
    }

    /**
     * Spring Security 흐름
     *
     * 1. 새로운 요청이 들어올 경우 항상
     * SecurityContextPersistenceFilter의 doFilter() 실행.
     * -> HttpSessionSecurityContextRepository의 locadContext() 실행.
     * -> 세션에 저장되어 있는 context를 가져옴. 없을 경우 새로 생성.
     *    (SecurityContextHolder가 ThreadLocalSecurityContextHolderStrategy에 ThreadLocal로 SecurityContext를 저장.)
     * -> 체인이 끝나면 SecurityContextHolder가 context를 비워줌.
     *
     * 2. 로그인 시 (로그인 성공 시)
     * AbstractAuthenticationProcessingFilter의 doFilter()가 실행
     * -> attemptAuthentication() 실행
     * -> 템플릿 메소드 패턴으로
     *    AbstractAuthenticationProcessingFilter를 상속하고 있는 UsernamePasswordAuthenticationFilter의 attemptAuthentication()이 실행됨.
     *    (UsernamePasswordAuthenticationFilter: 폼 인증을 처리하는 필터.)
     * 	  AuthenticationManager에 authentication 요청.
     * 	  기본적으로 AuthenticationManager를 상속하는 ProviderManager의 authentication() 실행.
     * -> authentication result가 없을 경우 parent의 authenticate()를 호출하여 result 저장.
     *    (여기에서 result는 Principal을 상속한 Authentication을 상속한 UsernamePasswordAuthenticationToken)
     * -> result가 있을 경우 크리덴셜을 삭제하고 result를 리턴.
     * -> AbstractAuthenticationProcessingFilter의 doFilter()로 돌아와서 authResult에 저장.
     * -> AbstractAuthenticationProcessingFilter의 successfulAuthentication() 실행하여
     *    SecurityContextHolder가 SecurityContext에 authResult를 저장.
     */

    /**
     * Spring Security Filter
     *
     * 1. WebAsyncManagerIntergrationFilter
     * 2. SecurityContextPersistenceFilter
     * 3. HeaderWriterFilter
     * 4. CsrfFilter
     * 5. LogoutFilter
     * 6. UsernamePasswordAuthenticationFilter
     * 7. DefaultLoginPageGeneratingFilter
     * 8. DefaultLogoutPageGeneratingFilter
     * 9. BasicAuthenticationFilter
     * 10. RequestCacheAwareFtiler
     * 11. SecurityContextHolderAwareReqeustFilter
     * 12. AnonymouseAuthenticationFilter
     * 13. SessionManagementFilter
     * 14. ExeptionTranslationFilter
     * 15. FilterSecurityInterceptor
     *
     * 이 모든 필터들은 FilterChainProxy가 호출.
     * 또 FilterChainProxy는 DelegatingFilterProxy에 의해서 호출.
     * WebSecurityConfigurerAdapter를 상속하여 커스텀한 SecurityConfig가 사용할 필터 체인 목록을 만드는 역할을 함.
     */

    /**
     * DelegatingFilterProxy와 FilterChainProxy
     *
     * 서블릿 필터
     * https://tomcat.apache.org/tomcat-5.5-doc/servletapi/javax/servlet/Filter.html
     *
     * 서블릿 필터의 구현체 DelegatingFilterProxy.
     * 서블릿 필터 처리를 스프링의 빈으로 위임하는 서블릿 필터.
     * DelegatingFilterProxy가 FilterChainProxy에게 필터 처리를 위임함.
     * (SecurityFilterAutoConfiguration을 보면 FilterChainProxy의 빈 이름이 'springSecurityFilterChain'으로 등록되는 것을 알 수 있음.
     *  이 빈 이름을 사용해서 필터 처리를 위임.)
     * 스프링 부트를 사용할 경우 자동으로 등록됨.
     *
     * SecurityFilterAutoConfiguration이 DelegatingFilterProxyRegistrationBean을 통해
     * FilterChainProxy을 빈 이름 'springSecurityFilterChain'으로 등록하고
     * DelegatingFilterProxy가 이 빈 이름으로 delegate(위임)를 함.
     * 그리고 FilterChainProxy가 SecurityConfig를 확인하여 15개의 필터들 중 사용할 필터들을 호출하는 역할을 함.
     */

    /**
     * Authorization(권한)
     * DelegatingFilterProxy -> FilterChainProxy -> FilterSecurityInterceptor -> AccessDecisionManager -> AccessDecisionVoter
     *
     * AccessDecisionManager
     * Access Control(Authrorization, 권한) 결정을 내리는 인터페이스로, 구현체 3가지를 기본으로 제공.
     * (1) AffirmativeBased: 여러 AccessDecisionVoter중에 하나의 voter라도 허용하면 허용. (기본 전략)
     *      모든 voter가 허용하지 않을 경우 exception 발생.
     *      AccessDecisionManager 인터페이스를 구현한 AffirmativeBased의 decide()가 호출됨.
     * (2) ConsensusBased: 다수결
     * (3) UnanimousBased: 만장일치
     *
     * AccessDecisionVoter
     * 해당 Authentication이 특정한 Object(patterns)에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인.
     * (ConfigAttribute: SecurityConfig에 설정한 permitAll()이나 hasRole() 등.)
     * WebExpressionVoter: 웹 시큐리티에서 사용하는 기본 구현체, ROLE_Xxxx가 매치하는지 확인.
     * RoleHierachyVoter: 계층형 ROLE 지원. AMDIN > MANAGER > USER. (ADMIN은 USER 권한도 가지도록..)
     *
     * FilterSecurityInterceptor
     * AccessDecisionManager를 사용하여 Access Control(Authorization, 권한) 또는 예외 처리하는 필터.
     * FilterChainProxy가 가지고 있는 여러개의 필터 중 하나.
     * 대부분의 경우 FilterChainProxy의 제일 마지막 필터로 들어있다. (접근이 가능한지 최종적으로 확인.)
     *
     * FilterSecurityInterceptor는 Filter를 구현하고 AbstractSecurityInterceptor를 상속하고 있음.
     * AbstractSecurityInterceptor의 beforeInvocation()에서
     * this.accessDecisionManager.decide(authenticated, object, attributes);
     * 이 부분에 디버깅을 걸면 AffirmativeBased를 기본적으로 사용하고 있는 것을 알 수 있음. (AffirmativeBased의 decide()를 호출.)
     *
     * 익명사용자(AnonymousAuthenticationToken)으로 인증이 필요한 페이지에 접근할 경우 AccessDeniedException 발생.
     * Exception을 처리하는 핸들러가 처리하여 로그인 페이지로 이동.
     * 로그인 후 인증이 처리되면 UsernamePasswordAuthenticationToken과 authorities=ROLE_USER를 가지게 됨.
     * ('/dashboard' 패턴의 object가 필요로 하는 attributes를 확인하면 'authenticated'라는 것을 확인할 수 있음.
     */

    /**
     * Exception 처리
     *
     * ExceptionTranslationFilter
     * 필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터.
     * (FilterSecurityInterceptor의 상위 클래스인 AbstractSecurityInterceptor에서 발생한 예외 처리기.)
     *
     * AuthenticationException 발생 시 (인증 에러)
     * AuthenticationEntryPoint 실행. (인증 처리기에 위임. 인증이 될 때까지 인증 시도.)
     * AbstractSecurityInterceptor 하위 클래스(예, FilterSecurityInterceptor)에서 발생하는 예외만 처리.
     * 그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는?
     *  -> UsernamePasswordAuthenticationFilter에서 발생한 에러(폼 로그인 시 발생하는 에러)는 ExceptionTranslationFilter에서 처리하지 않음.
     *     AbstractAuthenticationProcessingFilter(UsernamePasswordAuthenticationFitler의 상위 클래스) 내부에서 직접 처리.
     *     unsuccessfulAuthentication() -> saveException()이 호출되어 세션 애트리뷰트에 에러 메세지를 담아둠.
     *     이 에러 메세지를 기반으로 DefaultLoginPageGeneratingFilter가 로그인 페이지 뷰를 보여줄 때 에러 메세지를 같이 출력해줌.
     *
     * AccessDeniedException 발생 시 (접근 거부)
     * 익명 사용자라면 AuthenticationEntryPoint 실행. (인증을 하도록 인증 처리기에 위임.)
     * 익명 사용자가 아니라면(이미 인증된 사용자일 경우) AccessDeniedHandler에게 위임.
     *
     * 처음에 로그인하지 않은 상태에서 /dashboard 접근 시 AccessDeniedException 발생.
     *  -> sendStartAuthentication()으로 보내짐.
     * USER 권한을 가진 사용자가 로그인 후 ADMIN 권한의 페이지 접근 시에도 AccessDeniedException 발생.
     *  -> AccessDeniedHandler의 handle()로 보내짐.
     */
}
