package P2Anel;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Node.java
 * Uso: executar com argumento id (0..5)
 * Ex: java Node 0
 *
 * Comandos no console do nó:
 *  SEARCH arquivoX            -> busca (HMAC correto)
 *  TEST_BAD_HMAC arquivoX     -> envia SEARCH com HMAC incorreto (deve ser descartado)
 *  TEST_P7 arquivoX           -> envia SEARCH com origin=7 e HMAC incorreto (deve ser descartado)
 *  EXIT
 */
public class Node {
    private static final SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static final SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");
    private static final SecretKey chaveHMAC_ERRADA = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    private final int id;
    private final int porta;
    private final int portaSucessor;
    private final int portaAntecessor;
    private final Set<String> meusArquivos = ConcurrentHashMap.newKeySet();
    private final Set<String> cacheMensagens = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Deque<String> logRecebidos = new ConcurrentLinkedDeque<>();
    private final Deque<String> logEnviados = new ConcurrentLinkedDeque<>();
    private final ExecutorService pool = Executors.newCachedThreadPool();

    public Node(int id) {
        this.id = id;
        this.porta = 7000 + id;
        this.portaSucessor = 7000 + ((id + 1) % 6);
        this.portaAntecessor = 7000 + ((id + 5) % 6);
        inicializarArquivos();
    }

    private void inicializarArquivos() {
        int start = id * 10 + 1;
        int end = start + 9;
        for (int i = start; i <= end; i++) meusArquivos.add("arquivo" + i);
    }

    public void start() throws IOException {
        System.out.println("Nó P" + id + " iniciado na porta " + porta +
                " (sucessor: " + portaSucessor + ", antecessor: " + portaAntecessor + ")");
        ServerSocket server = new ServerSocket(porta);
        // thread que aceita conexões
        pool.execute(() -> {
            while (!server.isClosed()) {
                try {
                    Socket s = server.accept();
                    pool.execute(() -> {
                        try {
                            tratarConexao(s);
                        } catch (Exception e) {
                            System.err.println("Erro ao tratar conexão: " + e.getMessage());
                        }
                    });
                } catch (IOException e) {
                    System.err.println("ServerSocket accept error: " + e.getMessage());
                }
            }
        });

        // console interativo
        try (BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("Comandos: SEARCH <arquivoX> | TEST_BAD_HMAC <arquivoX> | TEST_P7 <arquivoX> | EXIT");
            while (true) {
                System.out.print("P" + id + "> ");
                String line = teclado.readLine();
                if (line == null) continue;
                line = line.trim();
                if (line.equalsIgnoreCase("EXIT")) {
                    System.out.println("Encerrando P" + id);
                    server.close();
                    pool.shutdownNow();
                    break;
                } else if (line.startsWith("SEARCH ")) {
                    String[] p = line.split("\\s+", 2);
                    if (p.length < 2) { System.out.println("Erro na entrada de dados. Tente outra vez!"); continue; }
                    enviarSearch(p[1], id, true);
                } else if (line.startsWith("TEST_BAD_HMAC ")) {
                    String[] p = line.split("\\s+", 2);
                    if (p.length < 2) { System.out.println("Erro na entrada de dados. Tente outra vez!"); continue; }
                    enviarSearchComHMACErrado(p[1], id);
                } else if (line.startsWith("TEST_P7 ")) {
                    String[] p = line.split("\\s+", 2);
                    if (p.length < 2) { System.out.println("Erro na entrada de dados. Tente outra vez!"); continue; }
                    enviarSearchComoP7(p[1]);
                } else {
                    System.out.println("Erro na entrada de dados. Tente outra vez!");
                }
            }
        } catch (IOException e) {
            System.err.println("Console IO error: " + e.getMessage());
        }
    }

    private void tratarConexao(Socket s) throws Exception {
        try (DataInputStream in = new DataInputStream(s.getInputStream())) {
            String linha = in.readUTF(); // preserva Base64 sem truncar
            // decifrar
            String dec;
            try {
                dec = CryptoUtils.decifrar(linha, chaveAES);
            } catch (Exception e) {
                logRecebidos.add("ERRO_DECIFRAR: " + linha);
                System.out.println("P" + id + " - Erro ao decifrar mensagem. Descartada.");
                return;
            }
            // formato: <payload>::<hmac>
            String[] partes = dec.split("::");
            if (partes.length < 2) {
                logRecebidos.add("SEM_HMAC: " + dec);
                System.out.println("P" + id + " - Mensagem sem HMAC recebida. Descartada.");
                return;
            }
            String payload = partes[0];
            String hmacRecebido = partes[1];

            // verificar HMAC
            boolean hmacValido;
            try {
                hmacValido = CryptoUtils.verificarHMAC(payload, hmacRecebido, chaveHMAC);
            } catch (Exception e) {
                hmacValido = false;
            }
            if (!hmacValido) {
                logRecebidos.add("HMAC_INVALIDO: " + payload);
                System.out.println("P" + id + " - HMAC inválido. Mensagem rejeitada.");
                return;
            }

            // log e processamento
            logRecebidos.add(payload);
            System.out.println("P" + id + " - Mensagem recebida: " + payload);

            // parse payload: tipo|arquivo|origin|msgid  (usamos campo chave=value separados por espaço)
            // Exemplo: "TYPE=SEARCH FILE=arquivo23 ORIGIN=2 ID=uuid"
            Map<String, String> mapa = parsePayload(payload);
            if (!mapa.containsKey("TYPE") || !mapa.containsKey("ID") || !mapa.containsKey("ORIGIN")) {
                System.out.println("P" + id + " - Payload com formato inválido. Descartado.");
                return;
            }
            String msgId = mapa.get("ID");
            String origin = mapa.get("ORIGIN");
            String type = mapa.get("TYPE");

            // evitar reprocessar mesma mensagem (prevenir loop)
            if (!cacheMensagens.add(msgId)) {
                // já visto
                System.out.println("P" + id + " - Mensagem " + msgId + " já processada. Ignorada.");
                return;
            }

            if (type.equalsIgnoreCase("SEARCH")) {
                String arquivo = mapa.get("FILE");
                if (arquivo == null) {
                    System.out.println("P" + id + " - SEARCH sem FILE. Descartada.");
                    return;
                }
                // se contém o arquivo, responde ao origin
                if (meusArquivos.contains(arquivo)) {
                    String respostaPayload = "TYPE=FOUND FILE=" + arquivo + " FOUND_AT=" + id + " ID=" + msgId;
                    enviarParaOrigin(origin, respostaPayload);
                    String log = "-> Enviada FOUND " + arquivo + " para origin " + origin;
                    logEnviados.add(log);
                    System.out.println("P" + id + " - Arquivo " + arquivo + " encontrado aqui. Resposta enviada para P" + origin);
                } else {
                    // encaminhar para sucessor (mantendo mesmo ID e origin)
                    String forwardPayload = payload; // já contem TYPE=SEARCH ...
                    encaminharParaSucessor(forwardPayload);
                    String log = "FORWARD -> " + forwardPayload + " para porta " + portaSucessor;
                    logEnviados.add(log);
                    System.out.println("P" + id + " - Arquivo " + arquivo + " não encontrado. Encaminhado ao sucessor.");
                }
            } else if (type.equalsIgnoreCase("FOUND")) {
                // resposta para origin: se origin == this node, mostrar resposta; caso contrário, encaminhar ao origin
                String arquivo = mapa.get("FILE");
                String foundAt = mapa.get("FOUND_AT");
                if (Integer.toString(id).equals(origin)) {
                    System.out.println("P" + id + " - RESPOSTA: arquivo " + arquivo + " está no nó P" + foundAt);
                } else {
                    // encaminhar para o sucessor; eventually the message will reach origin
                    encaminharParaSucessor(payload);
                    System.out.println("P" + id + " - Encaminhando FOUND para alcançar origin " + origin);
                }
            } else {
                System.out.println("P" + id + " - Tipo desconhecido: " + type);
            }

        } finally {
            try { s.close(); } catch (Exception ignore) {}
        }
    }

    private Map<String, String> parsePayload(String payload) {
        Map<String, String> m = new HashMap<>();
        String[] parts = payload.split("\\s+");
        for (String p : parts) {
            if (p.contains("=")) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) m.put(kv[0], kv[1]);
            }
        }
        return m;
    }

    private void enviarParaOrigin(String originStr, String payload) {
        try {
            int origin = Integer.parseInt(originStr);
            int portaOrigin = 7000 + origin;
            // gerar hmac e cifrar
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(payload, chaveHMAC);
            String cifrado = CryptoUtils.cifrar(payload + "::" + hmac, chaveAES, iv);
            try (Socket s = new Socket("localhost", portaOrigin);
                 DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                out.writeUTF(cifrado);
                out.flush();
            }
        } catch (Exception e) {
            System.err.println("P" + id + " - Erro ao enviar para origin: " + e.getMessage());
        }
    }

    private void encaminharParaSucessor(String payload) {
        try {
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(payload, chaveHMAC);
            String cifrado = CryptoUtils.cifrar(payload + "::" + hmac, chaveAES, iv);
            try (Socket s = new Socket("localhost", portaSucessor);
                 DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                out.writeUTF(cifrado);
                out.flush();
            }
        } catch (Exception e) {
            System.err.println("P" + id + " - Erro ao encaminhar para sucessor: " + e.getMessage());
        }
    }

    private void enviarSearch(String arquivo, int originId, boolean hmacCorreto) {
        String msgId = UUID.randomUUID().toString();
        String payload = "TYPE=SEARCH FILE=" + arquivo + " ORIGIN=" + originId + " ID=" + msgId;
        try {
            byte[] iv = CryptoUtils.gerarIV();
            SecretKey chaveHmacUsada = hmacCorreto ? chaveHMAC : chaveHMAC_ERRADA;
            String hmac = CryptoUtils.gerarHMAC(payload, chaveHmacUsada);
            String cifrado = CryptoUtils.cifrar(payload + "::" + hmac, chaveAES, iv);
            // enviar para o próprio nó (inserir na fila do anel)
            try (Socket s = new Socket("localhost", porta);
                 DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                out.writeUTF(cifrado);
                out.flush();
                logEnviados.add("SEARCH " + arquivo + " ID=" + msgId);
            }
        } catch (Exception e) {
            System.err.println("P" + id + " - Erro ao enviar SEARCH: " + e.getMessage());
        }
    }

    private void enviarSearchComHMACErrado(String arquivo, int originId) {
        enviarSearch(arquivo, originId, false);
        System.out.println("P" + id + " - Enviada SEARCH com HMAC inválido (test).");
    }

    private void enviarSearchComoP7(String arquivo) {
        // origin = 7 (fora do anel) e chave errada
        String msgId = UUID.randomUUID().toString();
        String payload = "TYPE=SEARCH FILE=" + arquivo + " ORIGIN=7 ID=" + msgId;
        try {
            byte[] iv = CryptoUtils.gerarIV();
            String hmac = CryptoUtils.gerarHMAC(payload, chaveHMAC_ERRADA);
            String cifrado = CryptoUtils.cifrar(payload + "::" + hmac, chaveAES, iv);
            // enviar para este nó mesmo (entra no anel)
            try (Socket s = new Socket("localhost", porta);
                 DataOutputStream out = new DataOutputStream(s.getOutputStream())) {
                out.writeUTF(cifrado);
                out.flush();
                logEnviados.add("SEARCH_P7 " + arquivo + " ID=" + msgId);
                System.out.println("P" + id + " - Enviada SEARCH simulando P7 com HMAC inválido.");
            }
        } catch (Exception e) {
            System.err.println("P" + id + " - Erro ao enviar SEARCH_P7: " + e.getMessage());
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
