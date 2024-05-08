package com.apirest.springsecuritydemo6.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtility {

    /*Este método é responsável por gerar um par de chaves RSA de 2048 bits.*/
    public static KeyPair generateRsaKey(){

        KeyPair keyPair;

        try {
            
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");   // cria uma instancia de KeyPairGenerator utilizando o algoritmo "RSA"
            keyPairGenerator.initialize(2048);                                           // Define o tamanho da chave em 2048 bits através do método initialize()
            keyPair = keyPairGenerator.generateKeyPair();                                        // As chaves são geradas chamando o método generateKeyPair() da instância de KeyPairGenerator.

        } catch (Exception e) {
            throw new IllegalStateException();
        }
        return keyPair;
    }
    
}
