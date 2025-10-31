package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;

public class TestClient {
    private static final SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static final SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");
    private static final SecretKey chaveErrada = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("Uso: java TestClient <portaNoAlvo> <arquivo> <origemId> <mode>");
            System.out.println("mode: ok | badhmac | p7");
            return;
        }
        int porta = Integer.parseInt(args[0]);
        String arquivo = args[1];
        int origin = Integer.parseInt(args[2]);
        String mode = args[3];

        String mensagem = "SEARCH " + arquivo + " " + origin;
        SecretKey hmacKey = chaveHMAC;
        if (mode.equalsIgnoreCase("badhmac") || mode.equalsIgnoreCase("p7")) hmacKey = chaveErrada;
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(mensagem, hmacKey);
        String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);

        try (Socket s = new Socket("localhost", porta);
             PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
            out.println(cifrado);
            System.out.println("Enviado para porta " + porta + " modo=" + mode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
