package sombrero.form;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    /**
     * Spring Security의 구조.
     * SecurityContextHolder > SecurityContext > Authentication
     *
     * SecurityContextHolder
     *  -> SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다. (하나의 스레드에서 자원 공간을 공유하 방식.)
     *                          한 스레드에 특화되어 있는 정보. 한 스레드 내에서는 어디에서나 접근 가능. 스레드가 다를 경우 같은 인증 정보를 가져올 수 없음.
     *                          ThreadLocal 외에 다른 전략 사용 필요.
     *                          async하게 threadpool을 사용하지 않는 이상 서블릿은 thread per request(스레드 하나 = 요청 하나)이므로 기본적으로 ThreadLocal 사용.
     * SecurityContext
     *  -> Authentication 제공.
     */
    public void dashboard() {

        /**
         * authentication: Principal과 GrantAuthority 제공.
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
         * principal: 인증한 사용자를 나타내는 정보.
         *            UserDetailsService에서 리턴한 UserDetails 타입의 객체.
         *
         *            * UserDetails: 애플리케이션이 가지고 있는 유저 정보와 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.
         *            * UserDetailsService: 유저 정보를 UserDetails 타입으로 가져오는 DAO(Data Access Object) 인터페이스.
         *
         * 디버깅 결과:
         * org.springframework.security.core.userdetails.User@59957021:
         *  Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true;
         *  AccountNonLocked: true; Granted Authorities: ROLE_USER
         */
        Object principal = authentication.getPrincipal();

        /**
         * authorities(GrantedAuthority): "ROLE_USER", "ROLE_ADMIN" 등 사용자가 가지고 있는 권한.
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
         * credentials: 인증할 때만 사용. (인증을 한 다음에는 값을 가지고 있을 필요가 없기 때문에 현재는 값이 없음.)
         *
         * 디버깅 결과:
         * credentials = null
         */
        Object credentials = authentication.getCredentials();

        /**
         * authenticated: 인증된 사용자인지 나타내는 정보.
         *
         * 디버깅 결과:
         * authenticated = true
         */
        boolean authenticated = authentication.isAuthenticated();

    }

}
