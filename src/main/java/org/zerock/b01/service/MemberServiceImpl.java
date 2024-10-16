package org.zerock.b01.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.zerock.b01.domain.Member;
import org.zerock.b01.domain.MemberRole;
import org.zerock.b01.dto.MemberJoinDTO;
import org.zerock.b01.repository.MemberRepository;

@Log4j2
@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService{

    private final ModelMapper modelMapper;  // 모델 객체 처리용

    private final MemberRepository memberRepository; // 회원가입

    private final PasswordEncoder passwordEncoder; // 암호 인코더


    @Override
    public void join(MemberJoinDTO memberJoinDTO) throws MidExistException {

        String mid = memberJoinDTO.getMid();

        boolean exist = memberRepository.existsById(mid);
        //단순히 존재 여부만 확인하면 되므로, existBy를 쓰는 것이 메서드 명으로 유추했을 때도, 리턴타입(boolean)

        if(exist){ // id가 중복되면 (exist가 true면) 예외처리
            throw new MidExistException();
        }

        Member member = modelMapper.map(memberJoinDTO, Member.class);
        member.changePassword(passwordEncoder.encode(memberJoinDTO.getMpw()));
        member.addRole(MemberRole.USER);

        log.info("=======================");
        log.info(member);  // 회원 객체
        log.info(member.getRoleSet()); // 룰 적용

        memberRepository.save(member);

    }
}
