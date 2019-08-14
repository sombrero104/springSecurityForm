package sombrero.account;

import org.springframework.security.test.context.support.WithMockUser;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * 커스텀 애노테이션
 * 테스트 시 임의로 만든 유저(실제 존재하지 않는 mock 유저) sombrero가 로그인한 상태에서 페이지 응답이 어떻게 나오는지 확인할 때 사용.
 */
@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "sombrero", roles = "USER")
public @interface WithUser {
}
