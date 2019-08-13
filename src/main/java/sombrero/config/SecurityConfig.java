package sombrero.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

    /**
     * Spring security에서 기본으로 만들어주는 user의 패스워드는
     * SecurityProperties에서 생성한 것을 받아서 UserDetailsServiceAutoConfiguration가 출력해 줌.
     * application.properties에 설정하면 출력하지 않음.
     */

    /**
     * {noop} : 기본 패스워드 인코더가 사용할 암호화 방식을 정의하는 prefix.
     *          form에서 입력한 패스워드를 이 prefix의 암호화 방식으로 암호화하여 비교함.
     *          'noop'은 암호화를 하지 않았다는 뜻.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sombrero").password("{noop}123").roles("USER").and()
                .withUser("admin").password("{noop}123").roles("ADMIN");
    }
}
