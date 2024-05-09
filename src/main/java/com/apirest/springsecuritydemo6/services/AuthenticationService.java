package com.apirest.springsecuritydemo6.services;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.apirest.springsecuritydemo6.dtos.LoginResponseDto;
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
    private AuthenticationManager authenticationManager;
    private TokenService tokenService;


    /*Este método é responsável por registrar um novo usuário. Ele recebe um nome de usuário e senha, codifica a senha usando o passwordEncoder, 
    * busca o papel de usuário no roleRepository, cria um conjunto de papéis, e então salva um novo ApplicationUser no userRepository com o nome 
    * de usuário, senha codificada e papéis.
    * */
    public ApplicationUser registerUser(String username, String password) {

        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();

        Set<Role> authorities = new HashSet<>();
        authorities.add(userRole);

        return userRepository.save(new ApplicationUser(0, username, encodedPassword, authorities));
    }

    /*Este método é responsável por realizar a autenticação de um usuário com um nome de usuário e senha, e gerar um token JWT para o usuário 
     * autenticado. Ele recebe dois parâmetros: username e password, que são utilizados para autenticar o usuário.*/
    public LoginResponseDto loginUser(String username, String password){

        try{
            // Tentativa de autenticar o usuário com o nome de usuário e senha fornecidos
            Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            // Geração de um token JWT para o usuário autenticado
            String token = tokenService.generateJwt(auth);

            // Retorna um objeto LoginResponseDto com as informações do usuário autenticado e o token JWT
            return new LoginResponseDto(userRepository.findByUsername(username).get(), token);

        } catch(AuthenticationException e){
            return new LoginResponseDto(null, "");
        }
    }

}

