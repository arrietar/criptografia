package com.rene.cripto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.Cipher;

public class Cripto {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generar un par de claves RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Cifrar un mensaje utilizando la clave pública
        PublicKey clavePublica = keyPair.getPublic();
        byte[] mensaje = "Hola, mundo!".getBytes("UTF-8");
        byte[] mensajeCifrado = rsaEncrypt(clavePublica, mensaje);

        // Descifrar el mensaje utilizando la clave privada
        PrivateKey clavePrivada = keyPair.getPrivate();
        byte[] mensajeDescifrado = rsaDecrypt(clavePrivada, mensajeCifrado);

        System.out.println("Mensaje original: " + new String(mensaje, "UTF-8"));
        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado, "UTF-8"));
        System.out.println("Mensaje descifrado: " + new String(mensajeDescifrado, "UTF-8"));
    }

    public static byte[] rsaEncrypt(PublicKey publicKey, byte[] mensaje) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(mensaje);
    }

    public static byte[] rsaDecrypt(PrivateKey privateKey, byte[] mensajeCifrado) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(mensajeCifrado);
    }
}


