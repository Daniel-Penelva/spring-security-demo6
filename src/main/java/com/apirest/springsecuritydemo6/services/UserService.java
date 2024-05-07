package com.apirest.springsecuritydemo6.services;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.apirest.springsecuritydemo6.models.ApplicationUser;
import com.apirest.springsecuritydemo6.models.Role;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println("In the user details service");

        if (!username.equals("Daniel"))
            throw new UsernameNotFoundException("Not Daniel");

        Set<Role> roles = new HashSet<>();
        roles.add(new Role(1, "USER"));

        return new ApplicationUser(1, "Daniel", passwordEncoder.encode("password"), roles);
    }

}
