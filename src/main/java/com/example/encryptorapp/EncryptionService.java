package com.example.encryptorapp;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class EncryptionService {

    
    
    public byte[] deriveKey(String password, byte[] salt, int iterations) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256); 
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    
    public byte[] encryptFile(byte[] plaintext, String password) throws Exception {
       
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        
        byte[] key = deriveKey(password, salt, 100000);

        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        
        byte[] ciphertext = cipher.doFinal(plaintext);

        
        byte[] combinedBytes = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, combinedBytes, 0, salt.length);
        System.arraycopy(iv, 0, combinedBytes, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, combinedBytes, salt.length + iv.length, ciphertext.length);

        return combinedBytes;
    }

    
    public byte[] decryptFile(byte[] encryptedData, String password) throws Exception {
        
        byte[] salt = Arrays.copyOfRange(encryptedData, 0, 16);
        byte[] iv = Arrays.copyOfRange(encryptedData, 16, 28);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 28, encryptedData.length);

        
        byte[] key = deriveKey(password, salt, 100000);

        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        
        byte[] decryptedText = cipher.doFinal(ciphertext);

        return decryptedText;
    }
}
