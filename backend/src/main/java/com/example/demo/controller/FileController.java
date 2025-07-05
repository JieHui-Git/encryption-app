package com.example.demo.controller;

import com.example.demo.service.EncryptAndZip;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;

@RestController
@RequestMapping("/api/files")
public class FileController {

    @PostMapping(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> encryptAndZip(@RequestParam("file") MultipartFile file) throws Exception {
        // Save uploaded file to temp file
        File tempInputFile = File.createTempFile("uploaded_", ".txt");
        try (InputStream in = file.getInputStream(); FileOutputStream out = new FileOutputStream(tempInputFile)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }

        // Encrypt and zip
        File encryptedZipFile = EncryptAndZip.encrypt(tempInputFile); // <-- your logic
        if (encryptedZipFile == null || !encryptedZipFile.exists()) {
            throw new RuntimeException("Encryption failed or file not created.");
        }

        // Return as response
        byte[] zipBytes = Files.readAllBytes(encryptedZipFile.toPath());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"encrypted_package.zip\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(zipBytes);
    }
}
