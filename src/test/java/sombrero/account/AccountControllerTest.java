package sombrero.account;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

    /**
     * (1-1) anonymous
     * 로그인을 하지 않은 상태에서 페이지 응답이 어떻게 나오는지 테스트.
     */
    @Test
    public void index_anonymous() throws Exception {
        mockMvc.perform(get("/").with(anonymous()))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * (1-2) anonymous 애노테이션 방법
     */
    @Test
    @WithAnonymousUser
    public void index_anonymous_annotation() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * (2-1) 인덱스 페이지에 USER 권한 사용자가 로그인한 경우.
     * 임의로 만든 유저(실제 존재하지 않는 mock 유저)가 로그인한 상태에서 페이지 응답이 어떻게 나오는지 테스트.
     */
    @Test
    public void index_user() throws Exception {
        mockMvc.perform(get("/").with(user("sombrero").roles("USER")))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * (2-2) 인덱스 페이지에 USER 권한 사용자가 로그인한 경우 애노테이션 방법.
     */
    @Test
    @WithMockUser(username = "sombrero", roles = "USER")
    public void index_user_annotation() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * (2-3) 인덱스 페이지에 USER 권한 사용자가 로그인한 경우 커스텀 애노테이션 방법.
     */
    @Test
    @WithUser
    public void index_user_custom_annotation() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * (3-1) admin 페이지에 USER 권한 사용자가 로그인한 경우.
     */
    @Test
    public void admin_user() throws Exception {
        mockMvc.perform(get("/admin").with(user("sombrero").roles("USER")))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    /**
     * (3-2) admin 페이지에 ADMIN 권한 사용자가 로그인한 경우.
     */
    @Test
    public void admin_admin() throws Exception {
        mockMvc.perform(get("/admin").with(user("admin").roles("ADMIN")))
                .andDo(print())
                .andExpect(status().isOk());
    }

    /**
     * form 로그인 테스트 (성공하는 경우).
     */
    @Test
    @Transactional
    public void login_success() throws Exception {
        String username = "sombrero";
        String password = "123";
        Account user = this.createUser(username, password);
        mockMvc.perform(formLogin().user(username).password(password))
                .andExpect(authenticated());
    }

    /**
     * 여러개의 테스트에서 같은 사용자 추가 시 중복 에러 발생.
     *  => 각 테스트마다 트랜잭션을 추가하여 실패 시 롤백되도록 설정하면 다른 테스트에 영향을 주지 않음.
     */
    @Test
    @Transactional
    public void login_success2() throws Exception {
        String username = "sombrero";
        String password = "123";
        Account user = this.createUser(username, password);
        mockMvc.perform(formLogin().user(username).password(password))
                .andExpect(authenticated());
    }

    /**
     * form 로그인 테스트 (실패하는 경우).
     */
    @Test
    @Transactional
    public void login_fail() throws Exception {
        String username = "sombrero";
        String password = "123";
        Account user = this.createUser(username, password);
        mockMvc.perform(formLogin().user(username).password("12345"))
                .andExpect(unauthenticated());
    }

    /**
     * 테스트 유저 생성.
     */
    private Account createUser(String username, String password) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword(password);
        account.setRole("USER");
        return accountService.createNew(account);
    }

}