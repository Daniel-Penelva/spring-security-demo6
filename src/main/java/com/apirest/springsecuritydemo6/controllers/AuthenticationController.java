package com.apirest.springsecuritydemo6.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.apirest.springsecuritydemo6.dtos.LoginResponseDto;
import com.apirest.springsecuritydemo6.dtos.RegistrationDto;
import com.apirest.springsecuritydemo6.models.ApplicationUser;
import com.apirest.springsecuritydemo6.services.AuthenticationService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
@AllArgsConstructor
public class AuthenticationController {

    private AuthenticationService authenticationService;

    // http://localhost:8000/auth/register
    @PostMapping("/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDto body) {
        return authenticationService.registerUser(body.getUsername(), body.getPassword());
    }

    // http://localhost:8000/auth/login
    @PostMapping("/login")
    public LoginResponseDto loginUser(@RequestBody RegistrationDto body){
        return authenticationService.loginUser(body.getUsername(), body.getPassword());
    }

}
