package org.zerock.b01.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

@Log4j2 // 403에러는 서버에서 사용자의 요청을 거부했다는 의미로 사용자가 로그인 되었지만 해당 작업을 수행할 수는 없는 경우
public class Custom403Handler implements AccessDeniedHandler {
    // 시큐리티 권한에 대한 강제 접근시 처리하는 핸들러 -> CustomSecurityConfig에서 활성화

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)throws IOException, ServletException{

        log.info("--------ACCESS DENIED--------------");

        response.setStatus(HttpStatus.FORBIDDEN.value());

        //JSON 요청이었는지 확인 -> JSON 데이터를 만들어 전송
        String contentType = request.getHeader("Content-Type");

        boolean jsonRequest = contentType.startsWith("application/json");

        log.info("isJOSN: " + jsonRequest);

        //일반 request -> form 태그의 요청이 403인 경우 로그인 페이지로 이동할 때 ACCESS_DENIED
        if (!jsonRequest) {

            response.sendRedirect("/member/login?error=ACCESS_DENIED");
        }
    }
}
