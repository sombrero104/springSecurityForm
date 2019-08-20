package sombrero.account;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

/**
 * java.security.Principal을 사용하지 않고,
 * UserDetails 타입인
 * Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
 * 를 본인 도메인이 제공하는(본인 도메인에서 사용자를 나타내는) 타입(Account)으로 사용하고 싶을 때.
 * 커스텀한 User를 생성.
 * (1) 스프링 시큐리티가 제공하는 User를 상속받는 UserAccount.java 생성.
 * (2) AccountService.java의 loadUserByUsername() 리턴 부분을
 *      return new UserAccount(account); 로 변경.
 * (3) SampleController에서 '@AuthenticationPrincipal UserAccount userAccount'를 인자로 받을 수 있게 됨.
 *     (SecurityContextHolder 안에 있는 principal(UserDetails 객체) 가져옴.)
 */
public class UserAccount extends User {

    private Account account;

    public UserAccount(Account account) {
        super(account.getUsername(), account.getPassword()
                , List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole())));
                // List.of()는 자바 버전 9 이상에서만 지원. (현재는 11 사용중.)
                // Module Settings > Modules > Language Level 변경.
                // pom.xml에서 configuration, properties에 버전 변경.
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }

}
