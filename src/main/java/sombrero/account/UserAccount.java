package sombrero.account;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

/**
 * @AuthenticationPrincipal로 SecurityContextHolder 안에 있는 principal(UserDetails 객체) 가져오기.
 * (Controller에서 인자로 받고 있는 java.security.Principal를
 *      SecurityContextHolder 안에 있는 principal(UserDetails 객체)로 사용하도록 변경하기.)
 * (1) UserAccount.java 생성.
 * (2) AccountService.java의 loadUserByUsername() 리턴 부분을
 *      return new UserAccount(account); 로 변경.
 * (3) Controller에서 '@AuthenticationPrincipal UserAccount userAccount'를 인자로 받을 수 있게 됨.
 */
public class UserAccount extends User {

    private Account account;

    public UserAccount(Account account) {
        super(account.getUsername(), account.getPassword()
                , List.of(new SimpleGrantedAuthority("ROLE_" + account.getRole())));
                // List.of()를 사용하기 위해선 자바 버전 11을 사용해야 함.
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }

}
