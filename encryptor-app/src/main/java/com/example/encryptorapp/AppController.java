package com.example.encryptorapp;

import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class AppController {

    @Autowired
    private EncryptionService encryptionService;

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> handleEncryption(
            @RequestParam("file") MultipartFile file,
            @RequestParam("password") String password) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please select a file to encrypt."));
        }

        try {
            byte[] encryptedBytes = encryptionService.encryptFile(file.getBytes(), password);
            ByteArrayResource resource = new ByteArrayResource(encryptedBytes);
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + file.getOriginalFilename() + ".enc");

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(encryptedBytes.length)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            // Return an error message as a JSON object for AJAX handling
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(Map.of("error", "Encryption Failed: An unexpected error occurred."));
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> handleDecryption(
            @RequestParam("file") MultipartFile file,
            @RequestParam("password") String password) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please select a file to decrypt."));
        }

        try {
            byte[] decryptedBytes = encryptionService.decryptFile(file.getBytes(), password);
            ByteArrayResource resource = new ByteArrayResource(decryptedBytes);
            String originalFilename = file.getOriginalFilename().replace(".enc", "");
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + originalFilename);

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(decryptedBytes.length)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            // Return an error message for wrong password or corrupt file
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(Map.of("error", "Decryption Failed: Invalid password or corrupt file."));
        }
    }
}
