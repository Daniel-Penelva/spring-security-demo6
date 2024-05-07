package com.apirest.springsecuritydemo6;

import java.util.HashSet;
import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.apirest.springsecuritydemo6.models.ApplicationUser;
import com.apirest.springsecuritydemo6.models.Role;
import com.apirest.springsecuritydemo6.repository.RoleRepository;
import com.apirest.springsecuritydemo6.repository.UserRepository;

@SpringBootApplication
public class SpringSecurityDemo6Application {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityDemo6Application.class, args);
	}

	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder){
		return args -> {
			if(roleRepository.findByAuthority("ADMIN").isPresent()) return;
			Role adminRole = roleRepository.save(new Role("ADMIN"));
			roleRepository.save(new Role("USER"));

			Set<Role> roles = new HashSet<>();
			roles.add(adminRole);

			ApplicationUser admin = new ApplicationUser(1, "admin", passwordEncoder.encode("password"), roles);
			userRepository.save(admin);
		};
	}

}

/*Lógica de Inicialização:
 * 1. O método run implementa a lógica de inicialização da aplicação.
 * 2. Verifica se já existe um papel (role) com a autoridade "ADMIN" no repositório de roles. Se existir, a inicialização é interrompida.
 * 3. Caso não exista, cria um novo papel "ADMIN" e salva no repositório de roles.
 * 4. Em seguida, cria e salva um papel "USER".
 * 5. Cria um conjunto (Set) de roles contendo apenas o papel "ADMIN".
 * 6. Cria um novo usuário administrador (admin) com ID 1, nome "admin", senha criptografada usando o PasswordEncoder fornecido e atribui o conjunto de roles criado anteriormente.
 * 7. Por fim, salva o usuário administrador no repositório de usuários.
 * 
 * Esse script é responsável por inicializar a aplicação com um papel de administrador (ADMIN) e um papel de usuário (USER), além de criar um 
 * usuário administrador com nome "admin" e senha "password". Essa lógica garante que a aplicação tenha um usuário administrador padrão ao ser 
 * iniciada pela primeira vez.
*/