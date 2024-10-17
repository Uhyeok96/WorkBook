package org.zerock.b01.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import org.zerock.b01.domain.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, String> {

    @EntityGraph(attributePaths = "roleSet")
    @Query("select m from Member m where m.mid = :mid and m.social = false")
    Optional<Member> getWithRoles(String mid);
    // 로그인시 룰을 같이 로딩 하는 구조, 직접 로그인 할 때 소셜 서비스를 통해
    // 회원 가입된 회원들이 같은 패스워드를 가지므로 일반 회원들만 가져오도록 social 속성값이 false인 사용자만 처리

    @EntityGraph(attributePaths = "roleSet")  // 753 추가
    Optional<Member> findByEmail(String email);
    // 소셜 로그인과 같은 db 계정 이메일인 경우 소셜 로그인 만드로도 로그인 자체가 완료 되어야 함.
    // email을 이용해 기존 회원인지 알아오는 코드

    // 762 추가 소셜로그인 암호 강제 변경
    @Modifying  // @Query는 주로 select 용이지만 @Modifying을 붙이면 insrt, update, delete 처리도 가능함.
    @Transactional
    @Query("update Member m set m.mpw =:mpw where m.mid = :mid ")
    void updatePassword(@Param("mpw") String password, @Param("mid") String mid);
}
