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

    /**
     * Derives a 256-bit key from a password and salt using PBKDF2.
     */
    public byte[] deriveKey(String password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256); // 256-bit key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * Encrypts a byte array using the given password.
     * @param plaintext The raw bytes of the file to encrypt.
     * @param password The password to use for encryption.
     * @return A single byte array containing the salt, IV, and ciphertext.
     */
    public byte[] encryptFile(byte[] plaintext, String password) throws Exception {
        // 1. Generate a random 16-byte salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        // 2. Derive the key
        byte[] key = deriveKey(password, salt, 100000);

        // 3. Get a Cipher instance for AES-GCM encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // 4. Generate a random 12-byte Initialization Vector (IV)
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        // 5. Configure and initialize the cipher for encryption
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);

        // 6. Encrypt the data
        byte[] ciphertext = cipher.doFinal(plaintext);

        // 7. Combine salt, IV, and ciphertext into a single byte array
        byte[] combinedBytes = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, combinedBytes, 0, salt.length);
        System.arraycopy(iv, 0, combinedBytes, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, combinedBytes, salt.length + iv.length, ciphertext.length);

        return combinedBytes;
    }

    /**
     * Decrypts a byte array using the given password.
     * @param encryptedData The byte array containing the salt, IV, and ciphertext.
     * @param password The password to use for decryption.
     * @return The original, decrypted file data as a byte array.
     */
    public byte[] decryptFile(byte[] encryptedData, String password) throws Exception {
        // 1. Extract salt, IV, and ciphertext from the combined byte array
        byte[] salt = Arrays.copyOfRange(encryptedData, 0, 16);
        byte[] iv = Arrays.copyOfRange(encryptedData, 16, 28);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 28, encryptedData.length);

        // 2. Re-derive the key using the extracted salt
        byte[] key = deriveKey(password, salt, 100000);

        // 3. Get a Cipher instance and initialize it for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);

        // 4. Decrypt the data. This will throw an AEADBadTagException if the password is wrong.
        byte[] decryptedText = cipher.doFinal(ciphertext);

        return decryptedText;
    }
}
