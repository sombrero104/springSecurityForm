package sombrero.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StopWatch;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 커스텀 Filter 만들기.
 */
public class LoggingFilter extends GenericFilterBean {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 커스텀 Filter 만들기 예제.
     * 로그인 시 얼마나 걸렸는지 찍는 필터.
     * SecurityConfig.java에 http.addFilter() 설정도 추가해야 함.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start(((HttpServletRequest)request).getRequestURI()); // 이 URI가 Task 이름이 됨.
        chain.doFilter(request, response); // 다음 필터 진행.
        stopWatch.stop();
        logger.info(stopWatch.prettyPrint());
    }

}
