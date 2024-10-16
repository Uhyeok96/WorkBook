package org.zerock.b01.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
@Setter
@ToString
public class MemberSecurityDTO extends User {

    // import org.springframework.security.core.userdetails.User; 부모클래스로 사용
    // 도메인으로 회원은 특별한 점은 없지만 시큐리티를 이용하는 경우 회원 dto는 해당 api에 맞게 작성되어야 함.
    // 스프링 시큐리티에서는 UserDetails라는 타입을 이용함

    // 필드
    private String mid;
    private String mpw;
    private String email;
    private boolean del;
    private boolean social;


    // 생성자 -> extends User 에서 받음
    // public MemberSecurityDTO(String username, String password, Collection<? extends GrantedAuthority> authorities) {
    // public MemberSecurityDTO(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
    public MemberSecurityDTO(String username, String password, String email, boolean del, boolean social, Collection<? extends GrantedAuthority> authorities) {
        //                              이름             암호          이메일          탈퇴,         소셜                         권한
        super(username, password, authorities);

        this.mid = username;
        this.mpw = password;
        this.email = email;
        this.del = del;
        this.social = social;

    }
}
