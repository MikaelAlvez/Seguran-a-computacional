package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class ServidorDNS {
    private static final int PORTA = 5000;
    private static Map<String, String> mapa = new ConcurrentHashMap<>();
    private static List<Socket> clientesConectados = new CopyOnWriteArrayList<>();

    // Chaves compartilhadas corretas
    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        inicializarMapa();
        ServerSocket servidor = new ServerSocket(PORTA);
        System.out.println("🟢 Servidor DNS iniciado na porta " + PORTA);

        while (true) {
            Socket cliente = servidor.accept();
            clientesConectados.add(cliente);
            new Thread(() -> {
                try {
                    tratarCliente(cliente);
                } catch (Exception e) {
                    System.out.println("Erro: " + e.getMessage());
                }
            }).start();
        }
    }

    private static void inicializarMapa() {
        for (int i = 1; i <= 10; i++) {
            mapa.put("servidor" + i, "192.168.0." + (i * 10));
        }
    }

    private static void tratarCliente(Socket cliente) throws Exception {
        BufferedReader entrada = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
        PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true);

        String linha;
        while ((linha = entrada.readLine()) != null) {
            try {
                String texto = CryptoUtils.decifrar(linha, chaveAES);
                String[] partes = texto.split("::");
                if (partes.length < 2) {
                    System.out.println("🚫 Mensagem descartada (sem HMAC)");
                    continue;
                }

                String mensagem = partes[0];
                String hmacRecebido = partes[1];

                if (!CryptoUtils.verificarHMAC(mensagem, hmacRecebido, chaveHMAC)) {
                    System.out.println("🚨 HMAC inválido - mensagem rejeitada!");
                    continue;
                }

                if (mensagem.startsWith("GET")) {
                    String nome = mensagem.split(" ")[1];
                    String endereco = mapa.getOrDefault(nome, "NÃO ENCONTRADO");
                    enviarMensagem(cliente, "RESPOSTA " + nome + " " + endereco);
                } else if (mensagem.startsWith("UPDATE")) {
                    String[] dados = mensagem.split(" ");
                    mapa.put(dados[1], dados[2]);
                    System.out.println("🔄 Atualizado: " + dados[1] + " → " + dados[2]);
                    notificarClientes("ATUALIZADO " + dados[1] + " " + dados[2]);
                }
            } catch (Exception e) {
                System.out.println("❌ Erro ao processar mensagem: " + e.getMessage());
            }
        }
    }

    private static void enviarMensagem(Socket cliente, String mensagem) throws Exception {
        PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true);
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(mensagem, chaveHMAC);
        String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
        saida.println(cifrado);
    }

    private static void notificarClientes(String msg) throws Exception {
        for (Socket c : clientesConectados) {
            try {
                enviarMensagem(c, msg);
            } catch (Exception ignored) {}
        }
    }
}
