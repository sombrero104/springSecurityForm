package sombrero.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import sombrero.account.AccountService;

@Configuration
@EnableWebSecurity
@Order(Ordered.LOWEST_PRECEDENCE - 50)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /*@Autowired
    AccountService accountService;*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
        // 필터 15개
    }

    /**
     * Spring security에서 기본으로 만들어주는 인메모리 user의 패스워드는
     * SecurityProperties에서 생성한 것을 받아서 UserDetailsServiceAutoConfiguration가 출력해 줌.
     * application.properties에 설정하면 출력하지 않음.
     */

    /**
     * {noop} : 기본 패스워드 인코더가 사용할 암호화 방식을 정의하는 prefix.
     *          form에서 입력한 패스워드를 이 prefix의 암호화 방식으로 암호화하여 비교함.
     *          'noop'은 암호화를 하지 않았다는 뜻.
     */
    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sombrero").password("{noop}123").roles("USER").and()
                .withUser("admin").password("{noop}123").roles("ADMIN");
    }*/

    /**
     * AuthenticationManagerBuilder에게 사용할 UserDetailsService를 알려줄 때
     * 아래처럼 정의하지 않아도 UserDetailsService를 구현한 AccountService가 빈으로 등록되어 있으면 자동으로 사용하게 됨.
     */
    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService);
    }*/
}
