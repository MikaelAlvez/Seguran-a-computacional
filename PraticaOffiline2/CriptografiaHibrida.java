package PraticaOffiline2;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CriptografiaHibrida {
    
    // Tamanho da chave AES em bits
    private static final int AES_KEY_SIZE = 128; 
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER = "AES/ECB/PKCS5Padding";
    private static final String RSA_CIPHER = "RSA/ECB/PKCS1Padding";

    // Geração de Chaves
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048); // 2048 bits para RSA
        return keyGen.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }
    
    // Carregamento/Salvamento de Chaves
    public static void savePublicKeyToFile(PublicKey key, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(key.getEncoded());
        }
    }
    
    public static PublicKey loadPublicKeyFromFile(String filename) throws Exception {
        byte[] keyBytes;
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyBytes = fis.readAllBytes();
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        return kf.generatePublic(spec);
    }
    
    public static PrivateKey loadPrivateKeyFromFile(String filename) throws Exception {
        byte[] keyBytes;
        try (FileInputStream fis = new FileInputStream(filename)) {
            keyBytes = fis.readAllBytes();
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
        return kf.generatePrivate(spec);
    }

    // Criptografia/Descriptografia de Chaves (RSA)
    // Criptografa a chave AES usando a Chave Pública
    public static byte[] encryptAESKeyWithRSA(SecretKey aesKey, PublicKey rsaPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    // Descriptografa a chave AES usando a Chave Privada 
    public static SecretKey decryptAESKeyWithRSA(byte[] encryptedAESKey, PrivateKey rsaPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(decryptedKeyBytes, AES_ALGORITHM);
    }
    
    // Criptografia/Descriptografia de Dados (AES)

    public static byte[] encryptAES(byte[] data, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] encryptedData, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedData);
    }

    // Serialização/Desserialização
    public static byte[] serialize(Object obj) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
            return bos.toByteArray();
        }
    }

    public static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return ois.readObject();
        }
    }
}