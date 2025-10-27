package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;

public class ClienteRequisitante {
    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");

    // Chave incorreta para teste de segurança
    private static SecretKey chaveHMAC_ERRADA = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5000);
        BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter saida = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));

        // Thread para receber mensagens do servidor
        new Thread(() -> {
            try {
                String linha;
                while ((linha = entrada.readLine()) != null) {
                    String decifrado = CryptoUtils.decifrar(linha, chaveAES);
                    System.out.println("\n📩 Recebido: " + decifrado);
                }
            } catch (Exception e) {
                System.out.println("Conexão encerrada.");
            }
        }).start();

        System.out.println("\n🧠 Teste de segurança automático:");
        enviarMensagemComHMACErrado(saida);
        enviarMensagemSemHMAC(saida);
        Thread.sleep(3000);

        System.out.println("✅ Operando normalmente\n");
        while (true) {
            System.out.print("Digite o nome do servidor: ");
            String nome = teclado.readLine();
            enviarMensagemCorreta(saida, nome);
        }
    }

    private static void enviarMensagemCorreta(PrintWriter saida, String nome) throws Exception {
        String msg = "GET " + nome;
        String hmac = CryptoUtils.gerarHMAC(msg, chaveHMAC);
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmac, chaveAES, iv);
        saida.println(cifrado);
    }

    private static void enviarMensagemComHMACErrado(PrintWriter saida) throws Exception {
        String msg = "GET servidor1";
        String hmacErrado = CryptoUtils.gerarHMAC(msg, chaveHMAC_ERRADA);
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmacErrado, chaveAES, iv);
        System.out.println("🚨 Enviando mensagem com HMAC incorreto...");
        saida.println(cifrado);
    }

    private static void enviarMensagemSemHMAC(PrintWriter saida) throws Exception {
        String msg = "GET servidor2::"; // sem HMAC
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg, chaveAES, iv);
        System.out.println("🚫 Enviando mensagem sem HMAC...");
        saida.println(cifrado);
    }
}

