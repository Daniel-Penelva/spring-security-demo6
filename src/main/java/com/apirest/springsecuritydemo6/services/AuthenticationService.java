package com.apirest.springsecuritydemo6.services;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.apirest.springsecuritydemo6.models.ApplicationUser;
import com.apirest.springsecuritydemo6.models.Role;
import com.apirest.springsecuritydemo6.repository.RoleRepository;
import com.apirest.springsecuritydemo6.repository.UserRepository;

import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class AuthenticationService {

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;

    public ApplicationUser registerUser(String username, String password) {

        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();

        Set<Role> authorities = new HashSet<>();
        authorities.add(userRole);

        return userRepository.save(new ApplicationUser(0, username, encodedPassword, authorities));
    }

}

/*Este método é responsável por registrar um novo usuário. Ele recebe um nome de usuário e senha, codifica a senha usando o passwordEncoder, 
 * busca o papel de usuário no roleRepository, cria um conjunto de papéis, e então salva um novo ApplicationUser no userRepository com o nome 
 * de usuário, senha codificada e papéis.
 * */