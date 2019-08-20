package sombrero.form;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import sombrero.account.Account;
import sombrero.account.AccountService;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SampleServiceTest {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;

    /**
     * SecurityConfig에 빈으로 등록해줌.
     */
    @Autowired
    AuthenticationManager authenticationManager;

    @Test
    public void dashboard() {
        /**
         * dashboard()가 @Secured("ROLE_USER") 이기 때문에 로그인하지 않으면 아래 에러 발생.
         * org.springframework.security.authentication.AuthenticationCredentialsNotFoundException:
         *  An Authentication object was not found in the SecurityContext
         */

        /**
         * 코드로 인증하는 방법.
         * 사용자 추가.
         */
        Account account = new Account();
        account.setRole("USER");
        account.setUsername("sombrero");
        account.setPassword("123");
        accountService.createNew(account);

        /**
         * 다시 DB에서 사용자 가져옴.
         */
        UserDetails userDetails = accountService.loadUserByUsername("sombrero");

        /**
         * DB에서 가져온 principal(userDetails)와 크리덴셜(패스워드 123)로 (userDetails의 패스워드와 직접 입력한 크리덴셜 패스워드 비교.)
         * UsernamePasswordAuthenticationToken을 만들어서
         * AuthenticationManager로 인증하여 (위에서 입력한 패스워드가 일치하다면) 인증된 Authentication이 만들어.
         */
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, "123");
        Authentication authentication = authenticationManager.authenticate(token);

        /**
         * 인증된 Authentication을 SecurityContextHolder에 넣어줌. 인증완료.
         */
        SecurityContextHolder.getContext().setAuthentication(authentication);

        /**
         * dashboard() 접근.
         */
        sampleService.dashboard();
    }

}