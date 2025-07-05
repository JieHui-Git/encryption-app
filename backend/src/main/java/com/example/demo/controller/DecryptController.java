package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.example.demo.service.UnzipAndDecrypt;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.core.io.Resource;
import org.springframework.core.io.FileSystemResource;
import java.io.File;

@RestController
public class DecryptController {

    @PostMapping("/api/files/decrypt")
    public ResponseEntity<?> decryptZip(@RequestParam("file") MultipartFile file) {
        try {
            File tempZip = File.createTempFile("input", ".zip");
            file.transferTo(tempZip);

            File decryptedFile = UnzipAndDecrypt.decrypt(tempZip);

            Resource resource = new FileSystemResource(decryptedFile);

            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"decrypted.txt\"")
                .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Decryption failed: " + e.getMessage());
        }
    }
}
