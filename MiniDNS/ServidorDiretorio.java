package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class ServidorDiretorio {
    private static final int PORTA = 6000;
    private static final Map<String, List<String>> servicos = new ConcurrentHashMap<>();
    private static final Map<String, Integer> roundRobinIndex = new ConcurrentHashMap<>();

    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        ServerSocket servidor = new ServerSocket(PORTA);
        System.out.println("🟢 Servidor de Diretório ativo na porta " + PORTA);

        while (true) {
            Socket cliente = servidor.accept();
            new Thread(() -> {
                try {
                    tratarCliente(cliente);
                } catch (Exception e) {
                    System.out.println("Erro: " + e.getMessage());
                }
            }).start();
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

                if (mensagem.startsWith("REGISTER")) {
                    String[] dados = mensagem.split(" ");
                    registrarServico(dados[1], dados[2]);
                    System.out.println("📦 Serviço registrado: " + dados[1] + " -> " + dados[2]);
                } else if (mensagem.startsWith("DISCOVER")) {
                    String[] dados = mensagem.split(" ");
                    String servico = dados[1];
                    String estrategia = dados.length > 2 ? dados[2] : "roundrobin";
                    String endereco = escolherServidor(servico, estrategia);
                    enviarMensagem(saida, "RESPOSTA " + servico + " " + endereco);
                    System.out.println("📨 Enviado endereço para serviço '" + servico + "': " + endereco);
                }

            } catch (Exception e) {
                System.out.println("❌ Erro: " + e.getMessage());
            }
        }
    }

    private static void registrarServico(String servico, String endereco) {
        servicos.computeIfAbsent(servico, k -> new ArrayList<>()).add(endereco);
        roundRobinIndex.putIfAbsent(servico, 0);
    }

    private static String escolherServidor(String servico, String estrategia) {
        List<String> lista = servicos.get(servico);
        if (lista == null || lista.isEmpty()) return "SERVIÇO_NÃO_ENCONTRADO";

        if (estrategia.equalsIgnoreCase("random")) {
            return lista.get(new Random().nextInt(lista.size()));
        } else { // Round Robin padrão
            int i = roundRobinIndex.get(servico);
            String escolhido = lista.get(i % lista.size());
            roundRobinIndex.put(servico, (i + 1) % lista.size());
            return escolhido;
        }
    }

    private static void enviarMensagem(PrintWriter saida, String mensagem) throws Exception {
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(mensagem, chaveHMAC);
        String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
        saida.println(cifrado);
    }
}
