package P2Anel;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.UUID;

public class TestClient {
    private static final SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static final SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");
    private static final SecretKey chaveErrada = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("Uso: java TestClient <portaNoAlvo> <arquivo> <originId> <mode>");
            System.out.println("mode: ok | badhmac | p7");
            return;
        }
        int porta = Integer.parseInt(args[0]);
        String arquivo = args[1];
        String origin = args[2];
        String mode = args[3];

        String msgId = UUID.randomUUID().toString();
        String payload = "TYPE=SEARCH FILE=" + arquivo + " ORIGIN=" + origin + " ID=" + msgId;
        SecretKey hmacKey = mode.equalsIgnoreCase("ok") ? chaveHMAC : chaveErrada;
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(payload, hmacKey);
        String cifrado = CryptoUtils.cifrar(payload + "::" + hmac, chaveAES, iv);

        try (Socket s = new Socket("localhost", porta);
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
            out.writeUTF(cifrado);
            out.flush();
            System.out.println("Enviado para porta " + porta + " mode=" + mode + " payloadID=" + msgId);
        }
    }
}
