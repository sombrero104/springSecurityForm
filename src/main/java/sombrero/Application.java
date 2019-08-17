package sombrero;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableAsync
public class Application {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        /**
         * return PasswordEncoderFactories.createDelegatingPasswordEncoder();
         *  => 기본적으로 bcrypt 사용.
         * http://localhost:8080/account/USER/sombrero/123 결과:
         * {
         *      "id":1
         *      ,"username":"sombrero"
         *      ,"password":"{bcrypt}$2a$10$Wgmkst4CHTIzfCGISlV5A.68m7l6HSCOAYxyPhtU0AvGrjTX85PSW"
         *      ,"role":"USER"
         *  }
         */
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
