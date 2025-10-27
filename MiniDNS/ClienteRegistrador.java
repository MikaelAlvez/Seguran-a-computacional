package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;

public class ClienteRegistrador {
    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");
    private static SecretKey chaveHMAC_ERRADA = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5000);
        PrintWriter saida = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        new Thread(() -> {
            try {
                String linha;
                while ((linha = entrada.readLine()) != null) {
                    String decifrado = CryptoUtils.decifrar(linha, chaveAES);
                    System.out.println("📩 Servidor respondeu: " + decifrado);
                }
            } catch (Exception e) {
                System.out.println("Conexão encerrada.");
            }
        }).start();

        // Teste de segurança: chave incorreta
        enviarUpdateComHMACErrado(saida);
        Thread.sleep(2000);

        // Atualizações válidas
        Map<String, String> novos = Map.of(
            "servidor1", "10.0.0.11",
            "servidor4", "10.0.0.44",
            "servidor9", "10.0.0.99"
        );

        for (var e : novos.entrySet()) {
            enviarUpdateCorreto(saida, e.getKey(), e.getValue());
            Thread.sleep(3000);
        }
    }

    private static void enviarUpdateCorreto(PrintWriter saida, String nome, String ip) throws Exception {
        String msg = "UPDATE " + nome + " " + ip;
        String hmac = CryptoUtils.gerarHMAC(msg, chaveHMAC);
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmac, chaveAES, iv);
        saida.println(cifrado);
        System.out.println("✅ Atualização enviada: " + nome + " → " + ip);
    }

    private static void enviarUpdateComHMACErrado(PrintWriter saida) throws Exception {
        String msg = "UPDATE servidor1 10.0.0.111";
        String hmacErrado = CryptoUtils.gerarHMAC(msg, chaveHMAC_ERRADA);
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmacErrado, chaveAES, iv);
        System.out.println("🚨 Enviando atualização com HMAC incorreto...");
        saida.println(cifrado);
    }
}
