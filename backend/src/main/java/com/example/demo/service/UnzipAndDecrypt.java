package com.example.demo.service;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class UnzipAndDecrypt {

    private static final String KEYPATH = "/home/ec2-user/cert/certificate.pfx"; // move your pfx file here
    private static final String KEYPASSWORD = "your_password";
    private static final String KEYALIAS = "mykey";

    private static final int RSA_KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static File decrypt(File finalZipFile) throws Exception {
        // Load keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(KEYPATH), KEYPASSWORD.toCharArray());

        Certificate cert = keystore.getCertificate(KEYALIAS);
        if (cert == null || !(cert instanceof java.security.cert.X509Certificate)) {
            throw new Exception("The certificate is not of type X509Certificate");
        }

        PrivateKey privateKey = (PrivateKey) keystore.getKey(KEYALIAS, KEYPASSWORD.toCharArray());
        if (privateKey == null) {
            throw new Exception("Private key not found for alias: " + KEYALIAS);
        }

        byte[] finalZipBytes = Files.readAllBytes(finalZipFile.toPath());

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(finalZipBytes);
        try (ZipInputStream zipInputStream = new ZipInputStream(byteArrayInputStream)) {
            ZipEntry entry;

            ByteArrayOutputStream encryptedPackageStream = null;
            byte[] sha3_384HashBytes = null;

            while ((entry = zipInputStream.getNextEntry()) != null) {
                if ("encrypted_package.zip".equals(entry.getName())) {
                    encryptedPackageStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = zipInputStream.read(buffer)) != -1) {
                        encryptedPackageStream.write(buffer, 0, len);
                    }
                } else if ("encrypted_package.zip.sha3".equals(entry.getName())) {
                    sha3_384HashBytes = readAllBytes(zipInputStream);
                }
                zipInputStream.closeEntry();
            }

            if (encryptedPackageStream == null || sha3_384HashBytes == null) {
                throw new IllegalStateException("Required files not found in the zip archive.");
            }

            byte[] encryptedPackageBytes = encryptedPackageStream.toByteArray();

            // SHA3-384 verification
            byte[] calculatedSha3_384Hash = createHash(encryptedPackageBytes, "SHA3-384");
            if (!MessageDigest.isEqual(calculatedSha3_384Hash, sha3_384HashBytes)) {
                throw new IllegalStateException("SHA3-384 hash verification failed.");
            }

            // Extract encrypted zip
            ByteArrayInputStream encryptedPackageInputStream = new ByteArrayInputStream(encryptedPackageBytes);
            try (ZipInputStream encryptedZipInputStream = new ZipInputStream(encryptedPackageInputStream)) {
                byte[] encryptedFileContent = null;
                byte[] sha3_256Hash = null;

                while ((entry = encryptedZipInputStream.getNextEntry()) != null) {
                    if ("encrypted_data.enc".equals(entry.getName())) {
                        encryptedFileContent = readAllBytes(encryptedZipInputStream);
                    } else if ("encrypted_data.enc.sha3".equals(entry.getName())) {
                        sha3_256Hash = readAllBytes(encryptedZipInputStream);
                    }
                    encryptedZipInputStream.closeEntry();
                }

                if (encryptedFileContent == null || sha3_256Hash == null) {
                    throw new IllegalStateException("Required files not found in the encrypted zip archive.");
                }

                // SHA3-256 verification
                byte[] calculatedSha3_256Hash = createHash(encryptedFileContent, "SHA3-256");
                if (!MessageDigest.isEqual(calculatedSha3_256Hash, sha3_256Hash)) {
                    throw new IllegalStateException("SHA3-256 hash verification failed.");
                }

                // Split AES key, IV, and content
                byte[] encryptedAesKey = new byte[RSA_KEY_SIZE];
                System.arraycopy(encryptedFileContent, 0, encryptedAesKey, 0, RSA_KEY_SIZE);

                byte[] iv = new byte[IV_SIZE];
                System.arraycopy(encryptedFileContent, RSA_KEY_SIZE, iv, 0, IV_SIZE);

                byte[] encryptedData = new byte[encryptedFileContent.length - RSA_KEY_SIZE - IV_SIZE];
                System.arraycopy(encryptedFileContent, RSA_KEY_SIZE + IV_SIZE, encryptedData, 0, encryptedData.length);

                // Decrypt AES key
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

                // Decrypt actual data
                SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
                byte[] decryptedData = aesCipher.doFinal(encryptedData);

                // Save and return temp file
                File outputFile = File.createTempFile("decrypted_", ".txt");
                try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                    fos.write(decryptedData);
                }
                return outputFile;
            }
        }
    }

    private static byte[] readAllBytes(ZipInputStream zipInputStream) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = zipInputStream.read(buffer)) != -1) {
            byteArrayOutputStream.write(buffer, 0, len);
        }
        return byteArrayOutputStream.toByteArray();
    }

    private static byte[] createHash(byte[] data, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }
}
