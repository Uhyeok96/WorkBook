package org.zerock.b01.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.zerock.b01.domain.Member;
import org.zerock.b01.repository.MemberRepository;
import org.zerock.b01.security.dto.MemberSecurityDTO;

import java.util.Optional;
import java.util.stream.Collectors;

@Log4j2
@Service
@RequiredArgsConstructor  // 690 passwordEncoder.encode시 주석 처리 // 728 재사용
public class CustomUserDetailService implements UserDetailsService {
    
    // 스프링 시큐리티 객체의 실제로 인증을 처리하는 UserDetailsService 인터페이스의 구현체가 있다.
    // 이 구현체를 내 마음대로 Custom 처리하는 클래스
    // UserDetailsService는 loadUserByUsername()이라는 메서드를 하나 가지고 있음
    // 실제 인증을 처리할 때 호출되는 부분임.

    // 필드
    // 728 제거 private PasswordEncoder passwordEncoder;

    // 생성자
    // 728 제거   public CustomUserDetailService(){
    // 728 제거       this.passwordEncoder = new BCryptPasswordEncoder();
    // 728 제거   }   // 현재 클래스가 동작시에 기본적으로 암호처리 객체를 생성

    private final MemberRepository memberRepository; // 728 추가

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        // 로그인시 id를 처리 담당하는 메서드
        // 리턴 객체는 UserDetails라는 객체임 -> 인증과 관련된 정보를 저장하는 역할!!!
        
        log.info("CustomUserDetailService.loadUserByUsername() 메서드 실행");
        log.info("username : " + username);

// 728 제거       UserDetails userDetails = User.builder()
//                .username("USER1")
//                // 암호화 안됨.password("1111")
//                .password(passwordEncoder.encode("1111"))
//                .authorities("ROLE_USER")   // user 권한
//                //.authorities("ROLE_ADMIN")
//                .build();

//        return userDetails;

        Optional<Member> result = memberRepository.getWithRoles(username);

        if(result.isEmpty()) {  // 해당 사용자가 없다면

            throw new UsernameNotFoundException("username not found");
        }

        Member member = result.get(); // 결과를 가져와 Member 엔티티 객체에 담는다.

        MemberSecurityDTO memberSecurityDTO = new MemberSecurityDTO( // Member 객체에 있는 값을 MemberSecurityDTO에 넣는다.
                member.getMid(),
                member.getMpw(),
                member.getEmail(),
                member.isDel(),
                false,
                member.getRoleSet().stream().map(memberRole -> new SimpleGrantedAuthority("ROLE_" + memberRole.name())).collect(Collectors.toList()) //룰을 가져와 콜렉션 처리함.
        );

        log.info("memberSecurityDTO---------");
        log.info(memberSecurityDTO);

        return memberSecurityDTO;  // 엔티티 객체를 가져와 dto로 리턴한다.
    }
}
