package org.zerock.b01.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.zerock.b01.dto.MemberJoinDTO;
import org.zerock.b01.service.MemberService;

@Controller
@RequestMapping("/member")
@Log4j2
@RequiredArgsConstructor
public class MemberController {
    // 스프링 시큐리티의 컨트롤러 역할

    // 의존성 주입
    private final MemberService memberService;
    
    @GetMapping("/login")
    public void loginGET(String error, String logout){
        // String logout -> http://localhost:8080/member/login?logout
        // String error id가 존재하지 않습니다? 에러처리용(로그인 과정에 문제시 처리)
        log.info("MemberController.loginGET() 메서드 실행");
        log.info("logout : " + logout);

        if(logout != null){
            log.info("사용자가 로그아웃함.....");
        }
    }

    @GetMapping("/join") // 731 추가
    public void joinGET(){
        log.info("join get...");
    }


    @PostMapping("/join") // 732 추가
    public String joinPOST(MemberJoinDTO memberJoinDTO, RedirectAttributes redirectAttributes){ //737 추가, RedirectAttributes redirectAttributes

        log.info("join post...");
        log.info(memberJoinDTO);

        try { // 737 추가
            memberService.join(memberJoinDTO);
        } catch (MemberService.MidExistException e) {

            redirectAttributes.addFlashAttribute("error", "mid");
            return "redirect:/member/join";
        }

        redirectAttributes.addFlashAttribute("result", "success");

        // 737 변경 return "redirect:/board/list"; // 가입 후 리스트
        return "redirect:/member/login"; //회원 가입 후 로그인
    }
}
