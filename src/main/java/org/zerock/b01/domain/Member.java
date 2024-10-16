package org.zerock.b01.domain;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "roleSet")
public class Member extends BaseEntity{
    // 시큐리티의 실제 사용자의 정보 로딩은 UserDetailsService를 이용해 처리함
    // db를 이용해서 설정함.

    @Id // pk 설정
    private String mid; // 회원 아이디

    private String mpw; // 회원 암호
    private String email; // 회원 이메일
    private boolean del;  // 탈퇴 여부

    private boolean social; // 소셜 로그인용

    @ElementCollection(fetch = FetchType.LAZY) // 각회원이 권한을 가질 수 있도록 필수 (지연로딩)
    //컬렉션 객체임을 JPA가 알 수 있게 하게 한다. 엔티티가 아닌 값 타입, 임베디드 타입에 대한 테이블을 생성하고 1대다 관계로 다룬다.
    @Builder.Default
    private Set<MemberRole> roleSet = new HashSet<>(); // 룰 적용

    public void changePassword(String mpw ){ // 암호 변경
        this.mpw = mpw;
    }

    public void changeEmail(String email){  //이메일 변경
        this.email = email;
    }

    public void changeDel(boolean del){  // 탈퇴
        this.del = del;
    }

    public void addRole(MemberRole memberRole){ // 룰추가
        this.roleSet.add(memberRole);
    }

    public void clearRoles() {  // 룰 제거
        this.roleSet.clear();
    }

    public void changeSocial(boolean social){this.social = social;}  // 소셜 전환
}
