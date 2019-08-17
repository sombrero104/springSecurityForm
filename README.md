
# Spring Security 구조<br/>

## Authentication(인증)<br/>

<pre>
DelegatingFilterProxy
 -> FilterChainProxy
 -> SecurityContextPersistenceFilter, UsernamePasswordAuthenticationFilter
 -> SecurityContextHolder -> SecurityContext
 -> AuthenticationManager
    (ProviderManager -> AuthenticationProvider(DaoAuthenticationProvider -> UserDetailsService))
 -> Authentication -> Principal, GrantedAuthorities
</pre>

#### 1. SecurityContextHolder
 -> SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다. (하나의 스레드에서 자원 공간을 공유하 방식.)<br/>
     한 스레드에 특화되어 있는 정보. 한 스레드 내에서는 어디에서나 접근 가능. 스레드가 다를 경우 같은 인증 정보를 가져올 수 없음.<br/>
     ThreadLocal 외에 다른 전략 사용 필요.<br/>
     async하게 threadpool을 사용하지 않는 이상 서블릿은 thread per request(스레드 하나 = 요청 하나)이므로 기본적으로 ThreadLocal 사용.<br/>

#### 2. SecurityContext
 -> Authentication 제공.<br/>

#### 3. authentication: Principal과 GrantAuthority 제공.

<pre>Authentication authentication = SecurityContextHolder.getContext().getAuthentication();</pre>

#### 4. principal: 인증한 사용자를 나타내는 정보. UserDetailsService에서 리턴한 UserDetails 타입의 객체.<br/>
UserDetails: 애플리케이션이 가지고 있는 유저 정보와 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.<br/>
UserDetailsService: 유저 정보를 UserDetails 타입으로 가져오는 DAO(Data Access Object) 인터페이스.<br/>
                  유저 정보를 스프링 시큐리티(Authentication Manager)에 제공하여 인증하도록 하는 역할.<br/>

<pre>
// Object principal = authentication.getPrincipal();
UserDetails userDetails = (UserDetails)authentication.getPrincipal();
</pre>

#### 5. authorities(GrantedAuthority): "ROLE_USER", "ROLE_ADMIN" 등 사용자가 가지고 있는 권한.<br/>
인증 이후, 인가 및 권한을 확인할 때 이 정보를 참조한다.<br/>
사용자가 가지고 있는 권한이 여러개일 수도 있으므로 컬렉션 타입.<br/>

<pre>
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
</pre>

#### 6. credentials: 인증할 때만 사용. (인증을 한 다음에는 값을 가지고 있을 필요가 없음.)

<pre>
Object credentials = authentication.getCredentials();
</pre>

#### 7. authenticated: 인증된 사용자인지 나타내는 정보.

<pre>
boolean authenticated = authentication.isAuthenticated();
</pre>
<br/>

### ** ThreadLocal 사용해보기.
커스텀 AccountContext에 ThreadLocal로 저장한 Account 정보 가져오기.
(SecurityContextHolder의 기본 전략이 ThreadLocal.)

<pre>
public void dashboard2() {
    Account account = AccountContext.getAccount();
    System.out.println("================================");
    System.out.println(account.getUsername());
    System.out.println("================================");
}
</pre><br/>

# Spring Security 흐름<br/>

#### 1. 새로운 요청이 들어올 경우 항상<br/>
SecurityContextPersistenceFilter의 doFilter() 실행.<br/>
-> HttpSessionSecurityContextRepository의 locadContext() 실행.<br/>
-> 세션에 저장되어 있는 context를 가져옴. 없을 경우 새로 생성.<br/>
   (SecurityContextHolder가 ThreadLocalSecurityContextHolderStrategy에 ThreadLocal로 SecurityContext를 저장.)<br/>
-> 체인이 끝나면 SecurityContextHolder가 context를 비워줌.<br/>

#### 2. 로그인 시 (로그인 성공 시)<br/>
AbstractAuthenticationProcessingFilter의 doFilter()가 실행<br/>
-> attemptAuthentication() 실행<br/>
-> 템플릿 메소드 패턴으로 AbstractAuthenticationProcessingFilter를 상속하고 있는 UsernamePasswordAuthenticationFilter의 attemptAuthentication()이 실행됨.<br/>
   (UsernamePasswordAuthenticationFilter: 폼 인증을 처리하는 필터.)<br/>
	  AuthenticationManager에 authentication 요청.<br/>
	  기본적으로 AuthenticationManager를 상속하는 ProviderManager의 authentication() 실행.<br/>
-> authentication result가 없을 경우 parent의 authenticate()를 호출하여 result 저장.<br/>
   (여기에서 result는 Principal을 상속한 Authentication을 상속한 UsernamePasswordAuthenticationToken)<br/>
-> result가 있을 경우 크리덴셜을 삭제하고 result를 리턴.<br/>
-> AbstractAuthenticationProcessingFilter의 doFilter()로 돌아와서 authResult에 저장.<br/>
-> AbstractAuthenticationProcessingFilter의 successfulAuthentication() 실행하여<br/>
   SecurityContextHolder가 SecurityContext에 authResult를 저장.<br/><br/><br/><br/>

## Spring Security Filter<br/>

1. WebAsyncManagerIntergrationFilter
2. SecurityContextPersistenceFilter
3. HeaderWriterFilter
4. CsrfFilter
5. LogoutFilter
6. UsernamePasswordAuthenticationFilter
7. DefaultLoginPageGeneratingFilter
8. DefaultLogoutPageGeneratingFilter
9. BasicAuthenticationFilter
10. RequestCacheAwareFtiler
11. SecurityContextHolderAwareReqeustFilter
12. AnonymouseAuthenticationFilter
13. SessionManagementFilter
14. ExeptionTranslationFilter
15. FilterSecurityInterceptor<br/><br/>

이 모든 필터들은 FilterChainProxy가 호출.
또 FilterChainProxy는 DelegatingFilterProxy에 의해서 호출.
WebSecurityConfigurerAdapter를 상속하여 커스텀한 SecurityConfig가 사용할 필터 체인 목록을 만드는 역할을 함.<br/><br/>

#### 1. WebAsyncManagerIntegrationFilter
스프링 MVC의 Async 기능(핸들러에서 Callable을 리턴할 수 있는 기능)을 사용할 때에도 SecurityContext를 공유하도록 도와주는 필터.<br/>
PreProcess: SecurityContext를 설정한다.<br/>
Callable: 비록 다른 쓰레드지만 그 안에서는 동일한 SecurityContext를 참조할 수 있다.<br/>
PostProcess: SecurityContext를 정리(clean up)한다.<br/>
(SampleController.java 파일의 asyncHandler(), asyncService() 참조.)<br/>


#### 2. SecurityContextPersistenceFilter
여러 요청간에 SecurityContext를 공유할 수 있 기능을 제공.<br/>
SecurityContextRepository(SecurityContextRepository의 구현체인 HttpSessionSecurityContextRepository)를 사용해서<br/>
기존의 세션에서 SecurityContext를 읽어오거나 초기화 한다. (SecurityContext가 없을 경우 새로 생성하는 역할도 함.)<br/>
이미 인증된 SecurityContext가 있을 경우 새로 만들지 않아도 되므 모든 인증 필터보다 먼저 실행되도록 선언되어 있음.<br/>
기본으로 사용하는 전략은 HTTP Session을 사용한다.<br/>
Spring-Session과 연동하여 세션 클러스터를 구현할 수 있다.<br/>


#### 3. HeaderWriterFilter
응답 헤더에 시큐리티 관련 헤더를 추가해주는 필터.<br/>

- XContentTypeOptionsHeaderWriter: 마임 타입 스니핑 방어.<br/>
    => 'X-Content-Type-Options: nosniff'를 헤더에 추가해줌.<br/>
- XXssProtectionHeaderWriter: 브라우저에 내장된 XSS 필터 적용.<br/>
    => 'X-XSS-Protection: 1; mode=block'을 헤더에 추가해줌.<br/>
- CacheControllHeadersWriter: 캐시 히스토리 취약점 방어. 동적인 페이지가 캐시되지 않도록.<br/>
    => 'Cache-Control: no-cache, no-store, max-age=0, must-revalidate'를 헤더에 추가해줌.<br/>
- HstsHeaderWriter: HTTPS로만 소통하도록 강제.<br/>
- XFrameOptionsHeaderWriter: clickjacking 방어.<br/>
    => 'X-Frame-Options: DENY'를 헤더에 추가해줌.<br/>

#### 4. CsrfFilter
CSRF(Cross-Site Request Forgery) 어택 방지 필터.<br/>
의도한 사용자만 리소스를 변경할 수 있도록 허용하는 필터. CSRF 토큰을 사용하여 방지.<br/>
서버쪽에서 만들어준 토큰이 있는지 확인.<br/>
** CSRF 어택: 인증된 유저의 계정을 사용해 악의적인 변경 요청을 만들어 보내는 기법.<br/>
            다른 도메인간에 요청을 허용하는 경우. API가 다른 도메인에서도 요청 가능한 경우.<br/>
            양방향간 인증하는 사용하지 않고 타도메인이라도 특정 도메인이 일치하면 허용하는 CORS를 사용하는 경우.<br/>
- 세션에 저장된 CSRF 토큰이 없을 경우 새로 생성하여 저장.
<pre>
    protected void doFilterInternal() {
        ...
        CsrfToken csrfToken = this.tokenRepository.loadToken(request);
            // HttpSessionCsrfTokenRepository의 loadToken()
        boolean missingToken = csrfToken == null;
        if (missingToken) {
            csrfToken = this.tokenRepository.generateToken(request);
            this.tokenRepository.saveToken(csrfToken, request, response);
        }
        CsrfToken csrfToken = this.tokenRepository.loadToken(request);
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        request.setAttribute(csrfToken.getParameterName(), csrfToken);
        ...
    }
</pre>
위와 같이 서버에서 생성하여 보내온 토큰 값을 form의 hidden값으로 가지고 있음.
<pre>
<input name="_csrf" type="hidden" value="5e06dffd-56a1-40e4-aad1-5dc4b4677719">
</pre>
폼 전송 후 서버에서 생성하여 보낸 토큰 값(csrfToken)과 폼에서 클라이언트가 보낸 토큰 값(actualToken)이 일치하는지 확인함.
<pre>
protected void doFilterInternal() {
    ...
    if (!this.requireCsrfProtectionMatcher.matches(request)) {
        filterChain.doFilter(request, response);
    } else {
        String actualToken = request.getHeader(csrfToken.getHeaderName());
        if (actualToken == null) {
            actualToken = request.getParameter(csrfToken.getParameterName());
        }
        if (!csrfToken.getToken().equals(actualToken)) {
            // MissingCsrfTokenException 혹은 InvalidCsrfTokenException 발생.
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
</pre>
디버깅 결과:
<pre>
----------------------------------------------------
csrfToken = {DefaultCsrfToken@11450}                 // 서버에서 생성하여 보낸 토큰 값
 token = "a50533f3-ac15-40c4-9503-3fc4b9e932f0"
----------------------------------------------------
actualToken = "a50533f3-ac15-40c4-9503-3fc4b9e932f0" // 클라이언트가 hidden form으로 보낸 토큰 값
----------------------------------------------------
</pre>

#### 5. LogoutFilter
#### 6. UsernamePasswordAuthenticationFilter
#### 7. DefaultLoginPageGeneratingFilter
#### 8. DefaultLogoutPageGeneratingFilter
#### 9. BasicAuthenticationFilter
#### 10. RequestCacheAwareFtiler
#### 11. SecurityContextHolderAwareReqeustFilter
#### 12. AnonymouseAuthenticationFilter
#### 13. SessionManagementFilter
#### 14. ExeptionTranslationFilter
#### 15. FilterSecurityInterceptor
<br/><br/><br/><br/>

#### DelegatingFilterProxy와 FilterChainProxy<br/>

서블릿 필터<br/>
https://tomcat.apache.org/tomcat-5.5-doc/servletapi/javax/servlet/Filter.html<br/>

서블릿 필터의 구현체 DelegatingFilterProxy.<br/>
서블릿 필터 처리를 스프링의 빈으로 위임하는 서블릿 필터.<br/>
DelegatingFilterProxy가 FilterChainProxy에게 필터 처리를 위임함.<br/>
(SecurityFilterAutoConfiguration을 보면 FilterChainProxy의 빈 이름이 'springSecurityFilterChain'으로 등록되는 것을 알 수 있음.<br/>
 이 빈 이름을 사용해서 필터 처리를 위임.)<br/>
스프링 부트를 사용할 경우 자동으로 등록됨.<br/>
스프링 부트 없이 스프링 시큐리티를 설정할 때는 AbstractSecurityWebApplicationInitializer를 상속 받아서 사용.<br/>

SecurityFilterAutoConfiguration이 DelegatingFilterProxyRegistrationBean을 통해
FilterChainProxy을 빈 이름 'springSecurityFilterChain'으로 등록하고
DelegatingFilterProxy가 이 빈 이름으로 delegate(위임)를 함.
그리고 FilterChainProxy가 SecurityConfig를 확인하여 15개의 필터들 중 사용할 필터들을 호출하는 역할을 함.<br/><br/><br/><br/>

## Authorization(권한)<br/>

<pre>
DelegatingFilterProxy -> FilterChainProxy
 -> FilterSecurityInterceptor
 -> AccessDecisionManager
    (AffirmativeBased -> AccessDecisionVoter(WebExpressionVoter -> SecurityExpressionHandler))
</pre><br/>

#### AccessDecisionManager
Access Control(Authrorization, 권한) 결정을 내리는 인터페이스로, 구현체 3가지를 기본으로 제공.<br/>
(1) AffirmativeBased: 여러 AccessDecisionVoter중에 하나의 voter라도 허용하면 허용. (기본 전략)<br/>
     모든 voter가 허용하지 않을 경우 exception 발생.<br/>
     AccessDecisionManager 인터페이스를 구현한 AffirmativeBased의 decide()가 호출됨.<br/>
(2) ConsensusBased: 다수결<br/>
(3) UnanimousBased: 만장일치<br/><br/>

#### AccessDecisionVoter
해당 Authentication이 특정한 Object(patterns)에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인.<br/>
(ConfigAttribute: SecurityConfig에 설정한 permitAll()이나 hasRole() 등.)<br/>
WebExpressionVoter: 웹 시큐리티에서 사용하는 기본 구현체, ROLE_Xxxx가 매치하는지 확인.<br/>
RoleHierachyVoter: 계층형 ROLE 지원. AMDIN > MANAGER > USER. (ADMIN은 USER 권한도 가지도록..)<br/><br/>

#### FilterSecurityInterceptor
AccessDecisionManager를 사용하여 Access Control(Authorization, 권한) 또는 예외 처리하는 필터.<br/>
FilterChainProxy가 가지고 있는 여러개의 필터 중 하나.<br/>
대부분의 경우 FilterChainProxy의 제일 마지막 필터로 들어있다. (접근이 가능한지 최종적으로 확인.)<br/><br/>

FilterSecurityInterceptor는 Filter를 구현하고 AbstractSecurityInterceptor를 상속하고 있음.<br/>
AbstractSecurityInterceptor의 beforeInvocation()에서<br/>
this.accessDecisionManager.decide(authenticated, object, attributes);<br/>
이 부분에 디버깅을 걸면 AffirmativeBased를 기본적으로 사용하고 있는 것을 알 수 있음. (AffirmativeBased의 decide()를 호출.)<br/><br/>

익명사용자(AnonymousAuthenticationToken)으로 인증이 필요한 페이지에 접근할 경우 AccessDeniedException 발생.<br/>
Exception을 처리하는 핸들러가 처리하여 로그인 페이지로 이동.<br/>
로그인 후 인증이 처리되면 UsernamePasswordAuthenticationToken과 authorities=ROLE_USER를 가지게 됨.<br/>
('/dashboard' 패턴의 object가 필요로 하는 attributes를 확인하면 'authenticated'라는 것을 확인할 수 있음.<br/><br/><br/>

## Exception 처리<br/>

#### ExceptionTranslationFilter
필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터.<br/>
(FilterSecurityInterceptor의 상위 클래스인 AbstractSecurityInterceptor에서 발생한 예외 처리기.)<br/><br/>

#### AuthenticationException 발생 시 (인증 에러)
AuthenticationEntryPoint 실행. (인증 처리기에 위임. 인증이 될 때까지 인증 시도.)<br/>
AbstractSecurityInterceptor 하위 클래스(예, FilterSecurityInterceptor)에서 발생하는 예외만 처리.<br/>
그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는?<br/>
 -> UsernamePasswordAuthenticationFilter에서 발생한 에러(폼 로그인 시 발생하는 에러)는 ExceptionTranslationFilter에서 처리하지 않음.<br/>
    AbstractAuthenticationProcessingFilter(UsernamePasswordAuthenticationFitler의 상위 클래스) 내부에서 직접 처리.<br/>
    unsuccessfulAuthentication() -> saveException()이 호출되어 세션 애트리뷰트에 에러 메세지를 담아둠.<br/>
    이 에러 메세지를 기반으로 DefaultLoginPageGeneratingFilter가 로그인 페이지 뷰를 보여줄 때 에러 메세지를 같이 출력해줌.<br/><br/>

#### AccessDeniedException 발생 시 (접근 거부)
익명 사용자라면 AuthenticationEntryPoint 실행. (인증을 하도록 인증 처리기에 위임.)<br/>
익명 사용자가 아니라면(이미 인증된 사용자일 경우) AccessDeniedHandler에게 위임.<br/><br/>

처음에 로그인하지 않은 상태에서 /dashboard 접근 시 AccessDeniedException 발생.<br/>
 -> sendStartAuthentication()으로 보내짐.<br/>
USER 권한을 가진 사용자가 로그인 후 ADMIN 권한의 페이지 접근 시에도 AccessDeniedException 발생.<br/>
 -> AccessDeniedHandler의 handle()로 보내짐.<br/><br/><br/><br/>

## WebSecurity
<pre>
The WebSecurity is created by WebSecurityConfiguration to create the FilterChainProxy
known as the Spring Security Filter Chain(springSecurityFilterChain).

the springSecurityFilterChain is the Filter that the DelegatingFilterProxy delegates to.

Customizations to the WebSecurity can be made by creating a WebSecurityConfigurer
or more likely by overriding WebSecurityConfigurerAdapter.
</pre>
<br/>

## HttpSecurity
<pre>
A HttpSecurity is similar to Spring Security's XML <http> element in the namespace configuration.
It allows configuring web based security for specific http requests.

By default it will be applied to all requests, but can be restricted using
#requestMatcher(RequestMatcher) or other similar methods.
</pre>

#### * Example Usage<br/>
The most basic form based configuration can be seen below.<br/>
The configuration will require that any URL that is requested will require a User with the role "ROLE_USER".<br/>
It also defines an in memory authentication scheme with a user that has the username "user", the password "password", and the role "ROLE_USER".<br/>
For additional examples, refer to the Java Doc of individual methods on HttpSecurity.<br/>

<pre>
@Configuration
@EnableWebSecurity
public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
    }
}
</pre>
<br/>




<br/><br/>