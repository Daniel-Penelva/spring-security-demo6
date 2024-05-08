package com.apirest.springsecuritydemo6.utils;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Data;

@Component
@Data
@AllArgsConstructor
public class RSAKeyProperties {

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    /*Construtor para inicializar as chaves pública e privada RSA.*/
    public RSAKeyProperties() {
        KeyPair pair = KeyGeneratorUtility.generateRsaKey();       // gera um par de chaves RSA
        this.publicKey = (RSAPublicKey) pair.getPublic();
        this.privateKey = (RSAPrivateKey) pair.getPrivate();
    }

}

/*Essa classe centraliza e simplifica o acesso às chaves RSA.*/