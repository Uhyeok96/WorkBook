package org.zerock.b01.service;

import org.zerock.b01.dto.MemberJoinDTO;

public interface MemberService {

    // 회원가입에는 이미 해당 아이디가 존재하는 경우 save는 insert가 아닌 update로 실행 되어야 함(카톡인증 중복 처리가 됨)

    static class MidExistException extends Exception {
        // 예외를 static 클래스로 선언해서 필요한 곳에서 사용함.
    }

    void join(MemberJoinDTO memberJoinDTO) throws MidExistException ;
}
