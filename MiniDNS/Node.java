package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class Node {
    private static final SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static final SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");

    private final int id;
    private final int porta;
    private final int portaSucessor;
    private final int portaAntecessor;
    private final List<String> meusArquivos = new ArrayList<>();
    private final List<String> logRecebidos = new CopyOnWriteArrayList<>();
    private final List<String> logEnviados = new CopyOnWriteArrayList<>();

    public Node(int id) {
        this.id = id;
        this.porta = 7000 + id;
        this.portaSucessor = 7000 + ((id + 1) % 6);
        this.portaAntecessor = 7000 + ((id + 5) % 6);
        inicializarArquivos();
    }

    private void inicializarArquivos() {
        // P0: arquivos 1-10, P1:11-20 etc.
        int start = id * 10 + 1;
        int end = start + 9;
        for (int i = start; i <= end; i++) {
            meusArquivos.add("arquivo" + i);
        }
    }

    public void start() throws Exception {
        System.out.println("Nó P" + id + " iniciado na porta " + porta +
                " (sucessor: " + (portaSucessor) + ", antecessor: " + (portaAntecessor) + ")");
        ServerSocket server = new ServerSocket(porta);

        // Thread para aceitar conexões
        new Thread(() -> {
            while (true) {
                try {
                    Socket s = server.accept();
                    new Thread(() -> {
                        try {
                            tratarConexao(s);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }).start();

        // prompt interativo para enviar buscas deste nó
        try (BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("Comandos: SEARCH <arquivoX>  | TEST_BAD_HMAC <arquivoX> | TEST_P7 <arquivoX> | EXIT");
            while (true) {
                System.out.print("P" + id + "> ");
                String line = teclado.readLine();
                if (line == null) continue;
                line = line.trim();
                if (line.equalsIgnoreCase("EXIT")) {
                    System.out.println("Encerrando P" + id);
                    System.exit(0);
                } else if (line.startsWith("SEARCH ")) {
                    String[] p = line.split(" ", 2);
                    if (p.length < 2) { System.out.println("Erro na entrada de dados. Tente outra vez!"); continue; }
                    enviarSearch(p[1], id, true); // HMAC correto
                } else if (line.startsWith("TEST_BAD_HMAC ")) {
                    String[] p = line.split(" ", 2);
                    enviarSearchComHMACErrado(p[1], id);
                } else if (line.startsWith("TEST_P7 ")) {
                    String[] p = line.split(" ", 2);
                    enviarSearchComoP7(p[1]);
                } else {
                    System.out.println("Erro na entrada de dados. Tente outra vez!");
                }
            }
        }
    }

    private void tratarConexao(Socket s) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
        PrintWriter out = new PrintWriter(s.getOutputStream(), true);
        String linha = in.readLine();
        s.close();
        if (linha == null) return;

        // decifra
        String dec;
        try {
            dec = CryptoUtils.decifrar(linha, chaveAES);
        } catch (Exception e) {
            logRecebidos.add("ERRO_DECIFRAR: " + linha);
            System.out.println("P" + id + " - Erro ao decifrar mensagem. Descartada.");
            return;
        }

        // formato esperado: "<mensagem>::<hmac>"
        String[] partes = dec.split("::");
        if (partes.length < 2) {
            logRecebidos.add("SEM_HMAC: " + dec);
            System.out.println("P" + id + " - Mensagem sem HMAC recebida. Descartada.");
            return;
        }

        String mensagem = partes[0];
        String hmacRecebido = partes[1];

        // verifica HMAC
        boolean hmacValido = false;
        try {
            hmacValido = CryptoUtils.verificarHMAC(mensagem, hmacRecebido, chaveHMAC);
        } catch (Exception e) {
            // erro ao calcular hmac
            hmacValido = false;
        }
        if (!hmacValido) {
            logRecebidos.add("HMAC_INVALIDO: " + mensagem);
            System.out.println("P" + id + " - HMAC inválido. Mensagem rejeitada.");
            return;
        }

        // log recebido válido
        logRecebidos.add(mensagem);
        System.out.println("P" + id + " - Mensagem recebida: " + mensagem);

        // processa tipos
        String[] campos = mensagem.split(" ");
        if (campos.length < 3) {
            System.out.println("P" + id + " - Mensagem com formato inválido. Descartada.");
            return;
        }

        String tipo = campos[0];
        if (tipo.equalsIgnoreCase("SEARCH")) {
            String arquivo = campos[1];
            int originId;
            try {
                originId = Integer.parseInt(campos[2]);
            } catch (NumberFormatException e) {
                System.out.println("P" + id + " - OriginId inválido. Descartada.");
                return;
            }

            // se eu tenho o arquivo, retorno FOUND ao origin
            if (meusArquivos.contains(arquivo)) {
                String resposta = "FOUND " + arquivo + " " + id;
                // envia para origin
                int portaOrigin = 7000 + originId;
                enviarRespostaPara(resposta, portaOrigin);
                logEnviados.add("-> " + resposta + " para P" + originId);
                System.out.println("P" + id + " - Arquivo " + arquivo + " encontrado aqui. Enviada resposta para P" + originId);
            } else {
                // reenviar para sucessor
                String forwardMsg = mensagem; // manter originId para resposta
                encaminharParaSucessor(forwardMsg);
                logEnviados.add("FORWARD -> " + forwardMsg + " para porta " + portaSucessor);
                System.out.println("P" + id + " - Arquivo " + arquivo + " não encontrado. Encaminhado ao sucessor (porta " + portaSucessor + ").");
            }
        } else if (tipo.equalsIgnoreCase("FOUND")) {
            // resposta final para o origin (quando origin é este nó, receberá aqui)
            String arquivo = campos[1];
            String nodeFound = campos[2];
            System.out.println("P" + id + " - RESPOSTA: arquivo " + arquivo + " está no nó P" + nodeFound);
        } else {
            System.out.println("P" + id + " - Tipo de mensagem desconhecido.");
        }
    }

    private void enviarRespostaPara(String mensagem, int portaDestino) {
        try {
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(mensagem, chaveHMAC);
            String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
            try (Socket s = new Socket("localhost", portaDestino);
                 PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
                out.println(cifrado);
            }
        } catch (Exception e) {
            System.out.println("P" + id + " - Erro ao enviar resposta: " + e.getMessage());
        }
    }

    private void encaminharParaSucessor(String mensagemSimples) {
        try {
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(mensagemSimples, chaveHMAC);
            String cifrado = CryptoUtils.cifrar(mensagemSimples + "::" + hmac, chaveAES, iv);
            try (Socket s = new Socket("localhost", portaSucessor);
                 PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
                out.println(cifrado);
            }
        } catch (Exception e) {
            System.out.println("P" + id + " - Erro ao encaminhar para sucessor: " + e.getMessage());
        }
    }

    private void enviarSearch(String arquivo, int originId, boolean hmacCorreto) {
        String mensagem = "SEARCH " + arquivo + " " + originId;
        try {
            SecretKey chaveHmacUsada = chaveHMAC;
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(mensagem, chaveHmacUsada);
            String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
            // enviar para este nó mesmo (entrando pela porta deste nó) para começar o circuito
            try (Socket s = new Socket("localhost", porta)) {
                PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                out.println(cifrado);
                logEnviados.add("SEARCH " + arquivo + " (origem P" + originId + ")");
            }
        } catch (Exception e) {
            System.out.println("P" + id + " - Erro ao enviar SEARCH: " + e.getMessage());
        }
    }

    private void enviarSearchComHMACErrado(String arquivo, int originId) {
        String mensagem = "SEARCH " + arquivo + " " + originId;
        try {
            // cria HMAC com chave errada
            SecretKey chaveErrada = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(mensagem, chaveErrada);
            String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
            try (Socket s = new Socket("localhost", porta)) {
                PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                out.println(cifrado);
                logEnviados.add("SEARCH_BAD_HMAC " + arquivo + " (origem P" + originId + ")");
                System.out.println("P" + id + " - Enviada SEARCH com HMAC inválido (test).");
            }
        } catch (Exception e) {
            System.out.println("P" + id + " - Erro ao enviar SEARCH_BAD_HMAC: " + e.getMessage());
        }
    }

    private void enviarSearchComoP7(String arquivo) {
        String mensagem = "SEARCH " + arquivo + " " + 7; // originId 7 (fora do anel)
        try {
            // aqui vamos enviar COM HMAC ERRADO para simular processo fora do anel com chave errada
            SecretKey chaveErrada = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(mensagem, chaveErrada);
            String cifrado = CryptoUtils.cifrar(mensagem + "::" + hmac, chaveAES, iv);
            // enviamos para este nó como se viesse de P7
            try (Socket s = new Socket("localhost", porta)) {
                PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                out.println(cifrado);
                logEnviados.add("SEARCH_P7 " + arquivo);
                System.out.println("P" + id + " - Enviada SEARCH simulando P7 com HMAC inválido.");
            }
        } catch (Exception e) {
            System.out.println("P" + id + " - Erro ao enviar SEARCH_P7: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Uso: java Node <nodeId(0-5)>");
            return;
        }
        int nodeId = Integer.parseInt(args[0]);
        if (nodeId < 0 || nodeId > 5) {
            System.out.println("nodeId inválido. Use 0..5");
            return;
        }
        Node node = new Node(nodeId);
        node.start();
    }
}
