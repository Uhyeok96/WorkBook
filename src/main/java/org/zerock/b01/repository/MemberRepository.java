package org.zerock.b01.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.zerock.b01.domain.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, String> {

    @EntityGraph(attributePaths = "roleSet")
    @Query("select m from Member m where m.mid = :mid and m.social = false")
    Optional<Member> getWithRoles(String mid);
    // 로그인시 룰을 같이 로딩 하는 구조, 직접 로그인 할 때 소셜 서비스를 통해
    // 회원 가입된 회원들이 같은 패스워드를 가지므로 일반 회원들만 가져오도록 social 속성값이 false인 사용자만 처리
}
