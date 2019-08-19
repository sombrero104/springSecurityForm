
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
서버쪽에서 만들어준 토큰이 있는지 확인. (disable 설정도 가능하지만 form 기반의 웹 페이지에서는 사용하는 것을 권장.)<br/>
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
- 위와 같이 서버에서 생성하여 보내온 토큰 값을 form의 hidden값으로 가지고 있음.<br/>
    (Thymeleaf 2.1 이상 버전을 사용하거나 jsp를 사용할 경우, form 태그를 사용하면 hidden으로 CSRF 토큰을 자동으로 넣어줌.<br/>
        GET 요청에는 토큰 값을 확인 안함. POST 요청만 토큰 확인. Postman으로 요청 테스트 가능.)<br/>
<pre>
❮input name="_csrf" type="hidden" value="5e06dffd-56a1-40e4-aad1-5dc4b4677719"❯
</pre>
- 폼 전송 후 서버에서 생성하여 보낸 토큰 값(csrfToken)과 폼에서 클라이언트가 보낸 토큰 값(actualToken)이 일치하는지 확인함.
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
- 즉, 다른 도메인이 아닌 해당 도메인에서 제공한 form이 맞다는 것을 확인함.
- 디버깅 결과:
<pre>
----------------------------------------------------
csrfToken = {DefaultCsrfToken@11450}                 // 서버에서 생성하여 보낸 토큰 값
    token = "a50533f3-ac15-40c4-9503-3fc4b9e932f0"
----------------------------------------------------
actualToken = "a50533f3-ac15-40c4-9503-3fc4b9e932f0" // 클라이언트가 hidden form으로 보낸 토큰 값
----------------------------------------------------
</pre>

#### 5. LogoutFilter
여러 LogoutHandler를 사용하여 로그아웃 시 필요한 처리를 하며 이후에는 LogoutSuccessHandler를 사용하여 로그아웃 후처리를 한다.<br/>
(로그아웃 버튼을 실제로 눌렀을때 수행되는 작업을 LogoutFilter가 처리.)<br/>
LogoutFilter.java -> doFilter() -> if(requiresLogout(request, response)) ...<br/>
    => 실제로 로그아웃 처리가 필요한 경우(로그아웃 POST 요청이 날아온 경우)에만 로그아웃 작업 수행.<br/>
- CompositeLogoutHandler(여러개의 LogoutHandler를 포함. 기본적으로는 아래 두개의 핸들러만 사용.)<br/>
    CsrfLogoutHandler, SecurityContextLogoutHandler<br/>
- LogoutSuccessHandler<br/>
    SimplUrlLogoutSuccessHandler<br/>

#### 6. UsernamePasswordAuthenticationFilter
폼 로그인을 처리하는 인증 필터. (로그인 시 submit 버튼을 누르면 수행되는 인 작업을 처리.)<br/>
사용자가 폼에 입력한 username과 password로 Authentication을 만들고 AuthenticationManager를 사용하여 인증을 시도한다.<br/>
AuthenticationManager(ProviderManager)는 여러 AuthenticationProvider를 사용하여 인증을 시도하는데,<br/>
(ProviderManager에도 여러 상속 구조를 가지고 있는데 자식 PorviderManager가 처리할 수 없으면 부모에게 위임하는 구조를 가지고 있다.)<br/>
그 중에 DaoAuthenticationProvider는 UserDetailsService를 사용하여 UserDetails 정보를 가져와 사용자가 입력한 password와 비교한다.<br/>

#### 7. DefaultLoginPageGeneratingFilter
기본 로그인 폼 페이지를 생성해주는 필터.<br/>
GET /login 요청을 처리하는 필터.<br/>
커스텀한 로그인 페이지를 만들 경우 SecurityConfig의 '커스텀한 로그인페이지를 만들 경우.' 라인 참조.<br/>

#### 8. DefaultLogoutPageGeneratingFilter
기본 로그아웃 폼 페이지를 생성해주는 필터.<br/>
GET /logout 요청을 처리하는 필터.<br/>

#### 9. BasicAuthenticationFilter
HTTP Basic 인증을 지원하는 필터.<br/>
SecurityConfig의 configure(HttpSecurity http)에 'http.httpBasic();' 설정을 추가하면 이 필터를 타게 됨.<br/>
** Basic 인증이란?<br/>
https://tools.ietf.org/html/rfc7617<br/>
요청 헤더에 username와 password를 실어 보내면 브라우저 또는 서버가 헤더에 있는 그 값을 읽어서 인증하는 방식.<br/>
예) Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l (username:password를 Base64로 인코딩한 것.)<br/>
한번 요청해서 인증이 되어도 그 다음 요청에서는 무효함. 요청마다 인증 필요.(remember me 기능을 추가하면 가능할지도 모르지만 필요 없음.)<br/>
보통, 브라우저 기반 요청이 클라이언트의 요청을 처리할 때 자주 사용.<br/>
보안에 취약하기 때문에 반드시 HTTPS를 사용할 것을 권장.<br/>
** 테스트:<br/>
curl의 아래 -u 옵션을 사용하면 헤더에 실어서 요청함.<br/>
curl -u sombrero:123 http://localhost:8080<br/>

#### 10. RequestCacheAwareFtiler
현재 요청과 관련 있는 캐시된 요청이 있는지 찾아서 적용하는 필터.<br/>
캐시된 요청이 없다면, 현재 요청 처리.<br/>
캐시된 요청이 있다면, 해당 캐시된 요청 처리.<br/>
캐시를 세션에 저장하고 가져다 씀.<br/>
<pre>
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
    HttpServletRequest wrappedSavedRequest
        = this.requestCache.getMatchingRequest((HttpServletRequest)request
            , (HttpServletResponse)response);
    chain.doFilter((ServletRequest)(wrappedSavedRequest == null ?
        request : wrappedSavedRequest), response);
}
</pre>
예) dashboard에 접근 시 로그인을 해야 하므로 login 페이지로 이동하게 됨.<br/>
이전 dashboard에 대한 요청을 wrappedSavedRequest에 저장해 놓음.<br/>
로그인 후 원래 처리해야 했던 요청인 dashboard 요청을 다시 처리.<br/>

#### 11. SecurityContextHolderAwareReqeustFilter
시큐리티 관련 서블릿 API를 구현해주는 필터. 서블릿3 스펙을 지원하는 역할.<br/>
서블릿3의 시큐리티 관련 메소드들을 스프링 시큐리티 기반으로 구현을 해주는 역할.<br/>
아래와 같은 서블릿3 메소드들..<br/>
<pre>
A Filter which populates the ServletRequest with a request wrapper
which implements the servlet API security methods.
SecurityContextHolderAwareRequestWrapper is extended to provide the following additional methods:
(1) HttpServletRequest#authenticate(HttpServletResponse) - Allows the user to
    determine if they are authenticated and if not send the user to the login page.
    See #setAuthenticationEntryPoint(AuthenticationEntryPoint).
(2) HttpServletRequest#login(String, String) - Allows the user to authenticate
    using the AuthenticationManager.
    See #setAuthenticationManager(AuthenticationManager).
(3) HttpServletRequest#logout() - Allows the user to logout using the
    LogoutHandlers configured in Spring Security.
    See #setLogoutHandlers(List).
(4) AsyncContext#start(Runnable) - Automatically copy the SecurityContext from
    the SecurityContextHolder found on the Thread that
    invoked AsyncContext#start(Runnable) to the Thread that processes the Runnable.
</pre>

#### 12. AnonymouseAuthenticationFilter
익명 인증 필터.<br/>
현재 SecurityContext에 Authentication이 null이면 '익명 Authentication'(AnonymousAuthenticationToken)을 만들어 넣어주고,<br/>
null이 아니면 아무일도 하지 않는다.<br/>
** Null Object Pattern: Null을 대변하는 객체를 만들어두는 패턴.<br/>

#### 13. SessionManagementFilter
SessionManagementFilter가 제공하는 기능들<br/>
(1) 세션 변조 방지 전략 설정: sessionFixation<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;세션 변조: https://www.owasp.org/index.php/Session_fixation<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;서블릿 컨테이너에 따라 세션 방지 전략이 달라짐.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;** 톰캣 버전에 따라 서블릿 버전 확인하기<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;http://tomcat.apache.org/whichversion.html<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- none<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- newSession<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- migrateSession (서블릿 3.0- 버전 컨테이너 사용시 기본값)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> http.sessionManagement().sessionFixation().migrateSession() 설정.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 인증 후 새로운 세션을 만들고 기존 세션에 있던 몇몇 세션 애트리뷰트 값들을 복사해옴.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- changeSessionId (서블릿 3.1+ 이상 버전에서만 지원. 컨테이너 사용시 기본값)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> http.sessionManagement().sessionFixation().changeSessionId() 설정.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 인증 후 새로운 세션을 만듬. 쿠키의 세션 Id를 바꿔서 보냄.<br/>
(2) 유효하지 않은 세션을 리다이렉트 시킬 URL 설정.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;http.sessionManagement().sessionFixation().changeSessionId().invalidSessionUrl("/login");<br/>
(3) 동시성 제어: maximumSessions<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;추가 로그인을 막을지 여부 설정. (기본값, false, 다른 브라우저에서 또 로그인 가능.)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;동시에 하나의 계정만 로그인 가능하도록 설정할 경우.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> http.sessionManagement().sessionFixation().changeSessionId().maximumSessions(1);<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(+) 다른 곳에서 로그인 시 현재 세션이 만료가 되었을 떄 보내고 싶은 Url 설정: .expiredUrl("/login");<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(+) 다른 곳에서 로그인 시 새로운 세션이 로그인 못하게 하고 싶을 때: .maxSessionsPreventsLogin(true);<br/>
(4) 세션 생성 전략: sessionCreationPolicy<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- IF_REQUIRED (기본값): 필요하면 만듬.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- NEVER: 스프링 시큐리티에선 만들지 않음. 하지만 기존에 이미 세션이 있다면 가져다 씀. (대부분 이미 존재하는 세션을 가져다 쓰게 됨.)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- STATELESS: 세션을 쓰지 않을 경우. 세션이 있더라도 쓰지 않음. stateless한 restAPI를 만 경우 사용.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- ALWAYS<br/><br/>
** 여러개의 서버간에 세션 공유 관리 시<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Spring session을 사용하면 스프링 세션 클러스터를 쉽고 편리하게 구성할 수 있음.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;https://spring.io/projects/spring-session<br/>

#### 14. ExceptionTranslationFilter
인증, 인가 에러 처리를 담당하는 필터.<br/>
ExceptionTranslationFilter -> FilterSecurityInterceptor(AccessDecisionManager, AffirmativeBased를 사용해서 인가 처리.)<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 반드시 FilterSecurityInterceptor 보다 이전에 처리되어야 함.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;FilterSecurityInterceptor가 ExceptionTranslationFilter를 감싸고 실행되어야 함.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;FilterSecurityInterceptor가 AccessDecisionManager, AffirmativeBased를 사용해서<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;권한에 대한 인가 처리를 하는데 두가지 에러가 발생할 수 있음.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ExceptionTranslationFilter는 아래 예외에 따라서 각각 다른 처리를 함.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(1) 인증 자체가 안된 경우 -> AuthenticationException<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> ExceptionTranslationFilter가 AuthenticationEntryPoint를 사용해서 예외를 처리.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> AuthenticationEntryPoint가 인증이 가능한 로그인 페이지로 보냄.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(2) 인증은 되어 있는데 해당 리소스에 대해 권한이 충분하지 않은 경우 -> AccessDeniedException<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> ExceptionTranslationFilter가 AccessDeniedHandler를 사용해서 예외를 처리.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 기본 처리는 403 에러 메세지를 보여주는 것.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 403 페이지 커스텀 -> http.exceptionHandling().accessDeniedPage("/access-denied");<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=> 403 페이지 커스텀 및 로그 남기기(AccessDeniedHandler 구현) -> SecurityConfig.java 파일 참조.

#### 15. FilterSecurityInterceptor
HTTP 리소스 시큐리티 처리를 담당하는 필터. AccessDecisionManager를 사용하여 인가를 처리한다.<br/>
- HTTP 리소스 시큐리티 설정. SecurityConfig.java 파일 참조.<br/>
<pre>
http.authorizeRequests()
    .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
    .mvcMatchers("/admin").hasAuthority("ROLE_ADMIN")
    .mvcMatchers("/user").hasRole("USER")
    .anyRequest().authenticated()
    .expressionHandler(expressionHandler());
</pre>
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