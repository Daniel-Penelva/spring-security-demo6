package com.apirest.springsecuritydemo6.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
@CrossOrigin("*")
public class AdminController {

    // http://localhost:8000/admin/
    @GetMapping("/")
    public String helloUserController() {
        return "Admin Acess level";
    }

}
