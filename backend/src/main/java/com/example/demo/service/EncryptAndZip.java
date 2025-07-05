package com.example.demo.service;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class EncryptAndZip {

    private static final Logger logger = Logger.getLogger(EncryptAndZip.class.getName());
    private static final int IV_SIZE = 16; // CBC mode typically uses 16-byte IVs
    private static final int RSA_KEY_SIZE = 256; // Adjust based on your RSA key size

    private static final String KEYSTORE_FILE = "C:\\Users\\jiehu\\Desktop\\encryptionTest\\encryptionTest\\cert\\certificate.pfx";
    private static final String KEYSTORE_PASSWORD = "your_password";
    private static final String KEY_ALIAS = "mykey";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encrypts the input file and produces a zipped encrypted package.
     * 
     * @param inputFile The file to encrypt.
     * @return The encrypted ZIP file.
     * @throws Exception On error.
     */
    public static File encrypt(File inputFile) throws Exception {
        // Load keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keystore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            logger.info("Alias found: " + alias);
        }

        Entry entry = keystore.getEntry(KEY_ALIAS, new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray()));
        if (!(entry instanceof PrivateKeyEntry)) {
            throw new IllegalStateException("The certificate entry is not of type PrivateKeyEntry");
        }
        PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) entry;
        X509Certificate cert = (X509Certificate) privateKeyEntry.getCertificate();
        PublicKey publicKey = cert.getPublicKey();

        // Generate AES key
        logger.info("Generating AES key...");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt AES key with RSA
        logger.info("Encrypting AES key with RSA...");
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Read the content of input file
        logger.info("Reading input file: " + inputFile.getAbsolutePath());
        byte[] fileContent = Files.readAllBytes(inputFile.toPath());

        // Encrypt data with AES-CBC
        logger.info("Encrypting data with AES-CBC...");
        byte[] iv = generateIV();
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedData = aesCipher.doFinal(fileContent);

        // Concatenate encrypted AES key, IV, and encrypted data
        byte[] encryptedFileContent = concatenate(encryptedAesKey, iv, encryptedData);

        // Create SHA3-256 hash of the encrypted content
        byte[] sha3_256Hash = createHash(encryptedFileContent, "SHA3-256");

        // Create zip file in memory
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ZipOutputStream zipOut = new ZipOutputStream(byteArrayOutputStream)) {
            addToZip(zipOut, "encrypted_data.enc", encryptedFileContent);
            addToZip(zipOut, "encrypted_data.enc.sha3", sha3_256Hash);
        }

        byte[] zipFileBytes = byteArrayOutputStream.toByteArray();

        // Create SHA3-384 hash of the zip file
        byte[] sha3_384Hash = createHash(zipFileBytes, "SHA3-384");

        // Write final zip file containing encrypted data and SHA3-384 hash to temp file
        File outputFile = File.createTempFile("final_package_", ".zip");
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             ZipOutputStream finalZipOut = new ZipOutputStream(fos)) {
            ZipEntry entry1 = new ZipEntry("encrypted_package.zip");
            finalZipOut.putNextEntry(entry1);
            finalZipOut.write(zipFileBytes);
            finalZipOut.closeEntry();

            ZipEntry entry2 = new ZipEntry("encrypted_package.zip.sha3");
            finalZipOut.putNextEntry(entry2);
            finalZipOut.write(sha3_384Hash);
            finalZipOut.closeEntry();
        }

        logger.info("Encryption and zipping complete: " + outputFile.getAbsolutePath());
        return outputFile;
    }

    private static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    private static void addToZip(ZipOutputStream zipOut, String entryName, byte[] data) throws Exception {
        ZipEntry entry = new ZipEntry(entryName);
        zipOut.putNextEntry(entry);
        zipOut.write(data);
        zipOut.closeEntry();
    }

    private static byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    private static byte[] createHash(byte[] data, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }
}
