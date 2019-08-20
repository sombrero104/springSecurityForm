package sombrero.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import sombrero.account.Account;
import sombrero.account.AccountContext;
import sombrero.account.AccountRepository;
import sombrero.account.UserAccount;
import sombrero.common.CurrentUser;
import sombrero.common.SecurityLogger;

import javax.sound.midi.SoundbankResource;
import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountRepository accountRepository;

    /**
     * index 페이지
     * (로그인한 사용자와 로그인하지 않은 사용자에 따라 첫페이지를 다르게 보이고 싶을 경우 principal 추가.)
     * (인덱스 페이지는 permitAll()로 설정했기 때문에 principal이 없어도 접근 가능. NullPointerException이 발생하지 않음.)
     */
    @GetMapping("/")
    /**
     * principal 인자로 가져오기
     * (1) java.security.Principal을 인자로 가져오는 방법.
     */
    // public String index(Model model, Principal principal) {
    /**
     * (2) User를 상속받는 UserAccount를 만들어서 @AuthenticationPrincipal로 가져오는 방법.
     */
    // public String index(Model model, @AuthenticationPrincipal UserAccount userAccount) {
    /**
     * (3) expression을 사용해서 Account를 가져오는 방법.
     */
    // public String index(Model model, @AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : account") Account account) {
    // 현재 객체가 익명사용자(anonymousUser)가 아닌 경우에는 principal 안에 들어있는 account를 가져오겠다는 뜻.
    /**
     * (4) 위에서 붙인 긴 애노테이션 expression을 여러곳에서 사용할 경우 너무 길기 때문에 @CurrentUser라는 커스텀 애노테이션으로 만듬.
     *      '@AuthenticationPrincipal(expression = "#this == 'anonymousUser' ? null : account")'
     *          => @CurrentUser
     */
    public String index(Model model, @CurrentUser Account account) {

        /**
         * 'public String index(Model model, Principal principal) {'
         * 에서 인자로 받는 principal은 java.security.Principal.
         * (참고로 Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
         *  의 principal과는 다름.
         *  아래처럼 가져와서 사용하는 SecurityContextHolder안에 들어있는 principal은
         *  Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
         *  은 UserDetails 타입임.)
         */
        /*if(principal == null) {
            model.addAttribute("message", "Hello Spring Security");
        } else {
            model.addAttribute("message", "Hello, " + principal.getName());
        }*/

        /**
         * java.security.Principal을 사용하지 않고,
         * UserDetails 타입인
         * Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
         * 를 본인 도메인이 제공하는(본인 도메인에서 사용자를 나타내는) 타입(Account)으로 사용하고 싶을 때.
         * Account에 접근할 수 있도록 커스텀한 User를 생성. (UserDeails 타입과 Account 타입의 어댑터 역할)
         * (1) 스프링 시큐리티가 제공하는 User를 상속받는 UserAccount.java 생성.
         * (2) AccountService.java의 loadUserByUsername() 리턴 부분을
         *      return new UserAccount(account); 로 변경.
         * (3) 여기에서 '@AuthenticationPrincipal UserAccount userAccount'를 인자로 받을 수 있게 됨.
         *     (SecurityContextHolder 안에 있는 principal(UserDetails를 상속한 User를 상속한 UserAccount 객체) 가져옴.)
         */
        /*if(userAccount == null) {
            model.addAttribute("message", "Hello Spring Security");
        } else {
            // userAccount.getAccount().getUsername() // Account를 꺼내서 사용하는 방법.
            model.addAttribute("message", "Hello, " + userAccount.getUsername());
        }*/
        if(account == null) {
            model.addAttribute("message", "Hello Spring Security");
        } else {
            model.addAttribute("message", "Hello, " + account.getUsername());
        }

        return "index";
    }

    /**
     * 로그인하지 않아도 볼 수 있는 info 페이지
     */
    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "info");
        return "info";
    }

    /**
     * 로그인한 사용자만 볼 수 있는 dashboard 페이지
     * (로그인하여 principal이 있어야 접근 가능한 페이지, principal이 없으면 null이 들어와서 NullPointerException 발생.)
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());

        // Spring Security의 구조 디버깅 해보기.
        sampleService.dashboard();

        // ThreadLocal 사용해보기.
        AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));
        sampleService.dashboard2();

        return "dashboard";
    }

    /**
     * ADMIN 권한으로 로그인한 사용자만 볼 수 있는 admin 페이지
     */
    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello admin, " + principal.getName());
        return "admin";
    }

    /**
     * USER 권한으로 로그인한 사용자만 볼 수 있는 user 페이지
     */
    @GetMapping("/user")
    public String user(Model model, Principal principal) {
        model.addAttribute("message", "Hello user, " + principal.getName());
        return "user";
    }

    /**
     * WebAsyncManagerIntegrationFilter
     * (+) Callable 사용해보기.
     *
     * 출력 결과:
     * ---------------------------------------------------
     * # MVC
     * # thread.getName(): http-nio-8080-exec-6
     * # principal: org.springframework.security.core.userdetails.User@59957021: Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
     * ---------------------------------------------------
     * ---------------------------------------------------
     * # Callable
     * # thread.getName(): task-1
     * # principal: org.springframework.security.core.userdetails.User@59957021: Username: sombrero; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER
     * ---------------------------------------------------
     *
     * 스레드는 다르지만 동일한 Principal을 사용하는 것을 확인할 수 있다.
     * 같은 Principal을 사용하도록 해주는 필터가 WebAsyncManagerIntegrationFilter 이다.
     *
     * 스프링 MVC의 Async 기능(핸들러에서 Callable을 리턴할 수 있는 기능)을 사용할 때에도 SecurityContext를 공유하도록 도와주는 필터.
     * PreProcess: SecurityContext를 설정한다.
     * Callable: 비록 다른 쓰레드지만 그 안에서는 동일한 SecurityContext를 참조할 수 있다.
     * PostProcess: SecurityContext를 정리(clean up)한다.
     */
    @GetMapping("/async-handler")
    @ResponseBody
    public Callable<String> asyncHandler() {
        SecurityLogger.log("MVC");

        // 1. 리턴하는 곳까지의 스레드는 톰캣의 nio 스레드.
        return () -> { // 2. Callable로 별도의 스레드가 새로 생성됨.
            SecurityLogger.log("Callable");
            return "Acync Handler";
        };

        // 위는 람다 버전. (같은 내용.)
        /*return new Callable<String>() { // 1. 리턴하는 곳까지의 스레드는 톰캣의 nio 스레드.
            @Override
            public String call() throws Exception { // 2. Callable로 별도의 스레드가 새로 생성됨.
                SecurityLogger.log("Callable");
                return "Acync Handler";
            }
        };*/
    }

    @GetMapping("/async-service")
    @ResponseBody
    public String asyncService() {
        SecurityLogger.log("MVC, before async service");
        sampleService.asyncService();
        SecurityLogger.log("MVC, after async service");
        return "Async Service";
    }

}
