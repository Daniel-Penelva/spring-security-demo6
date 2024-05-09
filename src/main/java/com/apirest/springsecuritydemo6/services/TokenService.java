package com.apirest.springsecuritydemo6.services;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class TokenService {

    private JwtEncoder jwtEncoder;

    /*Método para gerar um token JWT a partir de uma autenticação*/
    public String generateJwt(Authentication auth){

        Instant now = Instant.now();                                                       // Obtém o momento atual

        String scope = auth.getAuthorities().stream()                                      // Obtém as autoridades (roles) do usuário autenticado e as concatena em uma string de "scope"
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()                                       // Constrói as reivindicações (claims) do token JWT
            .issuer("self")                                                                // Emissor do token
            .issuedAt(now)                                                                 // Data de emissão
            .subject(auth.getName())                                                       // Assunto (nome do usuário autenticado)
            .claim("roles", scope)                                                         // Reivindicação de roles do usuário
            .build();                                                                      // Constrói o objeto JwtClaimsSet

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();       // Codifica as reivindicações em um token JWT e retorna o valor do token
    }
}

/*A classe TokenService é responsável por gerar tokens JWT a partir de informações de autenticação de um usuário.*/