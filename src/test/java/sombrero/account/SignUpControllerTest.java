package sombrero.account;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SignUpControllerTest {

    @Autowired
    MockMvc mockMvc;

    /**
     * form에 CSRF가 자동으로 들어오는지 확인.
     */
    @Test
    public void signUpForm() throws Exception {
        mockMvc.perform(get("/signup"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")));
    }

    /**
     * form submit 테스트.
     * submit 후 정상적으로 리다이렉트 되면 성공.
     * with(csrf()) 설정으로 CSRF 토큰을 넣어줌.
     */
    @Test
    public void processSignUp() throws Exception {
        mockMvc.perform(post("/signup")
                .param("username", "sombrero")
                .param("password", "123")
                .with(csrf())) // CSRF 토큰을 넣어줌.
                .andDo(print())
                .andExpect(status().is3xxRedirection());
    }

}