package com.apirest.springsecuritydemo6.dtos;

import com.apirest.springsecuritydemo6.models.ApplicationUser;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponseDto {

    private ApplicationUser applicationUser;
    private String jwt;
    
}
