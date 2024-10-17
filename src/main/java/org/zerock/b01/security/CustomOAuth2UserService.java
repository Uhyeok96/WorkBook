package org.zerock.b01.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.zerock.b01.domain.Member;
import org.zerock.b01.domain.MemberRole;
import org.zerock.b01.repository.MemberRepository;
import org.zerock.b01.security.dto.MemberSecurityDTO;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository; // 755 추가
    private final PasswordEncoder passwordEncoder; // 755 추가

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        log.info("CustomOAuth2UserService.loadUser() 메서드 실행");
        log.info(userRequest);

        log.info("oauth2 user...................");

        // 750 추가
        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        String clientName = clientRegistration.getClientName();

        log.info("NAME: " + clientName);

        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> paramMap = oAuth2User.getAttributes();

//      751 제거  paramMap.forEach((k, v) -> {
//            log.info("----------------------------------");
//            log.info(k + " : " + v);
//        });

        String email = null;

        switch (clientName){
            case "kakao":
                email = getKakaoEmail(paramMap);  // 하단에 메서드 추가
                break;
        }

        log.info("===============================");
        log.info(email);
        log.info("===============================");

        // 750 교체return super.loadUser(userRequest);
        // 756 교체return oAuth2User;
        return generateDTO(email, paramMap);  // 하단에 메서드 추가 필수
    }

    private String getKakaoEmail(Map<String, Object> paramMap){  // 카카오 전용 코드  752 추가

        log.info("KAKAO-----------------------------------------");

        Object value = paramMap.get("kakao_account");

        log.info(value);

        LinkedHashMap accountMap = (LinkedHashMap) value;

        String email = (String)accountMap.get("email");

        log.info("email..." + email);

        return email;
    }

    private MemberSecurityDTO generateDTO(String email, Map<String, Object> params){

        Optional<Member> result = memberRepository.findByEmail(email);

        //데이터베이스에 해당 이메일을 사용자가 없다면
        if(result.isEmpty()){
            //회원 추가 -- mid는 이메일 주소/ 패스워드는 1111
            Member member = Member.builder()
                    .mid(email)
                    .mpw(passwordEncoder.encode("1111"))
                    .email(email)
                    .social(true)
                    .build();
            member.addRole(MemberRole.USER);
            memberRepository.save(member);

            //MemberSecurityDTO 구성 및 반환
            MemberSecurityDTO memberSecurityDTO =
                    new MemberSecurityDTO(email, "1111",email,false, true, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
            memberSecurityDTO.setProps(params);

            return memberSecurityDTO;
        }else {
            Member member = result.get();
            MemberSecurityDTO memberSecurityDTO =
                    new MemberSecurityDTO(
                            member.getMid(),
                            member.getMpw(),
                            member.getEmail(),
                            member.isDel(),
                            member.isSocial(),
                            member.getRoleSet()
                                    .stream().map(memberRole -> new SimpleGrantedAuthority("ROLE_"+memberRole.name()))
                                    .collect(Collectors.toList())
                    );

            return memberSecurityDTO;

            // 카카오 로그인으로 가입한 회원의 암호는 1111로 강제 적용 됨 -> 사옹자 정보를 일반 회원으로 수정하도록 해야 함.
        }
    }


}
