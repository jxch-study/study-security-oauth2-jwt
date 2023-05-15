package org.jxch.study.ssoj.entity.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenSubject {
    private String userid;
    private String passwd;
}
