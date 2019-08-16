package sombrero.form;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import sombrero.account.Account;
import sombrero.account.AccountContext;

import java.util.Collection;

@Service
public class SampleService {

    /**
     * Spring Security의 구조.
     * SecurityContextHolder > SecurityContext > Authentication
     *
     * 1. SecurityContextHolder
     *  -> SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다. (하나의 스레드에서 자원 공간을 공유하 방식.)
     *                          한 스레드에 특화되어 있는 정보. 한 스레드 내에서는 어디에서나 접근 가능. 스레드가 다를 경우 같은 인증 정보를 가져올 수 없음.
     *                          ThreadLocal 외에 다른 전략 사용 필요.
     *                          async하게 threadpool을 사용하지 않는 이상 서블릿은 thread per request(스레드 하나 = 요청 하나)이므로 기본적으로 ThreadLocal 사용.
     * 2. SecurityContext
     *  -> Authentication 제공.
     */
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
        Object principal = authentication.getPrincipal();

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
     * WebSecurityConfigurerAdapter를 상속하여 커스텀한 SecurityConfig가 사용할 필터 체인 목록을 만드는 역할을 함.
     */
}
