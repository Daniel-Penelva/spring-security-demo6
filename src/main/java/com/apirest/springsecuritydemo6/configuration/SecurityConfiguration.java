package com.apirest.springsecuritydemo6.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.apirest.springsecuritydemo6.utils.RSAKeyProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfiguration {

    private final RSAKeyProperties keys;

    public SecurityConfiguration(RSAKeyProperties keys){
        this.keys = keys;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authManager(UserDetailsService detailsService){
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(detailsService);
        daoProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(daoProvider);
    }

    @SuppressWarnings("removal")
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/auth/**").permitAll();
                auth.requestMatchers("/admin/**").hasRole("ADMIN");
                auth.requestMatchers("/user/**").hasAnyRole("ADMIN", "USER");
                auth.anyRequest().authenticated();
            });
            
        http.oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                
        return http.build();
    }

    /*Este método é responsável por validar e decodificar os tokens JWT recebidos, verificando a assinatura digital com a chave pública.*/
    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();
    }

    /*Este método é responsável por codificar e assinar tokens JWT*/
    @Bean
    public JwtEncoder jwtEncoder(){
        JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    /*OBS. Os dois métodos acima são comumente utilizados em aplicações que utilizam JWT para autenticação e autorização. Eles permitem que a 
     * aplicação possa tanto decodificar e validar tokens JWT recebidos, quanto gerar novos tokens JWT assinados digitalmente. Portanto, o método 
     * jwtEncoder() é responsável por codificar e assinar tokens JWT, enquanto o método jwtDecoder() é utilizado para decodificar e validar tokens 
     * JWT. Ambos os métodos são essenciais para a manipulação segura e eficiente de tokens JWT em uma aplicação Spring.
     * */


    /*Esse método é responsável por configurar o JwtAuthenticationConverter para que ele possa extrair as autoridades (roles) do token JWT e 
     * convertê-las em um objeto de autenticação que pode ser utilizado pela aplicação.
     * */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();   // Cria uma instância de JwtGrantedAuthoritiesConverter
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");                   // Define o nome da reivindicação (claim) que contém as autoridades (roles)
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");                             // Define o prefixo a ser adicionado às autoridades (roles)
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();                             // Cria uma instância de JwtAuthenticationConverter
        jwtConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);                         // Retorna o JwtAuthenticationConverter configurado
        return jwtConverter;
    }

}
