package MiniDNS;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALG = "HmacSHA256";

    public static byte[] gerarIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String cifrar(String texto, SecretKey chave, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, chave, new IvParameterSpec(iv));
        byte[] cifrado = cipher.doFinal(texto.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(cifrado);
    }

    public static String decifrar(String textoCifrado, SecretKey chave) throws Exception {
        String[] partes = textoCifrado.split(":");
        byte[] iv = Base64.getDecoder().decode(partes[0]);
        byte[] cifrado = Base64.getDecoder().decode(partes[1]);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, chave, new IvParameterSpec(iv));
        return new String(cipher.doFinal(cifrado), "UTF-8");
    }

    public static String gerarHMAC(String mensagem, SecretKey chaveHmac) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(chaveHmac);
        byte[] hmacBytes = mac.doFinal(mensagem.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static boolean verificarHMAC(String mensagem, String hmacRecebido, SecretKey chaveHmac) throws Exception {
        String hmacCalculado = gerarHMAC(mensagem, chaveHmac);
        return hmacCalculado.equals(hmacRecebido);
    }
}
