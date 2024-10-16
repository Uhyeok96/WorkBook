package org.zerock.b01.dto;

import lombok.Data;

@Data
public class MemberJoinDTO {

    // 회원 가입용 DTO
    private String mid;
    private String mpw;
    private String email;
    private boolean del;
    private boolean social;
}
