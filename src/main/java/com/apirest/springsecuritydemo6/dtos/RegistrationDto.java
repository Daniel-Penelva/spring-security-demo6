package com.apirest.springsecuritydemo6.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationDto {

    private String username;
    private String password;

    public String toString() {
        return "Registration info: username: " + this.username + " password: " + this.password;
    }
}
