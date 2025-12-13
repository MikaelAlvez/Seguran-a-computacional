package PraticaOffiline2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

public class ServidorDatacenter {
    public static final String SERVER_IP = "127.0.0.1";
    public static final int TCP_PORT = 8888; // Porta de Ingestão (Borda)
    public static final int CLIENT_PORT = 8080; // Porta de Consulta (Cliente Gestor)
    
    public static final String DATACENTER_PUB_KEY_FILE = "datacenter.pub";
    public static final String DATABASE_FILE = "datacenter_db.txt";
    
    private static PrivateKey rsaPrivateKey;
    private static PublicKey authPublicKey;
    
    private static final List<DadosColetados> dadosHistoricos = Collections.synchronizedList(new LinkedList<>());
    
    // FIREWALL FW2: Lista de IPs da Borda permitidos (Simulação de Segmentação)
    private static final Set<String> IPS_BORDA_PERMITIDOS = new HashSet<>(Arrays.asList(
        "127.0.0.1",      // Localhost (simulação)
        "192.168.1.50",   // IP simulado da Borda
        "10.0.0.100"      // Outro IP simulado da Borda
    ));

    public static void main(String[] args) {
        try {
            System.out.println("==============================================");
            System.out.println("     DATACENTER - Sistema de Armazenamento    ");
            System.out.println("==============================================\n");
            
            // 1. Geração e Salvamento da Chave Pública RSA do Datacenter
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, DATACENTER_PUB_KEY_FILE);
            System.out.println("✅ Chaves RSA do Datacenter geradas.");
            System.out.println("📄 Chave pública salva em: " + DATACENTER_PUB_KEY_FILE);

            // 2. Carrega a Chave Pública do Servidor de Autenticação
            try {
                authPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
                System.out.println("✅ Chave pública de Autenticação carregada.");
            } catch (Exception e) {
                System.err.println("⚠️  Aviso: Não foi possível carregar chave de Auth (não crítico para operação).");
            }

            // 3. Carrega dados de sessões anteriores
            loadDataFromDatabase();
            System.out.println("📊 Carregados " + dadosHistoricos.size() + " registros do banco de dados.");
            
            System.out.println("\n--- DATACENTER INICIADO ---");
            System.out.println("🔒 FIREWALL FW2 ATIVO:");
            System.out.println("   → Porta " + TCP_PORT + " (Ingestão): Apenas IPs da Borda permitidos");
            System.out.println("   → Porta " + CLIENT_PORT + " (Consulta): Aberta para Clientes autenticados");
            System.out.println("==============================================\n");
            
            ExecutorService executor = Executors.newFixedThreadPool(3);
            
            // Listener para a Borda (Ingestão)
            executor.submit(ServidorDatacenter::startBordaListener);
            
            // Listener para o Cliente (Consulta)
            executor.submit(ServidorDatacenter::startClientListener);
            
        } catch (Exception e) {
            System.err.println("❌ Erro fatal no Datacenter: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void startBordaListener() {
        try (ServerSocket serverSocket = new ServerSocket(TCP_PORT)) {
            System.out.println("🌐 Listener de Ingestão ATIVO na porta TCP " + TCP_PORT + " (Aguardando Borda)...\n");
            
            while (true) {
                Socket clientSocket = serverSocket.accept();
                
                // FIREWALL FW2: Proxy de Aplicação (Verifica Origem/IP)
                String ipOrigem = clientSocket.getInetAddress().getHostAddress();
                
                if (!IPS_BORDA_PERMITIDOS.contains(ipOrigem)) {
                    System.err.println("🚨 FW2 BLOQUEIO: Conexão na porta " + TCP_PORT + " de IP NÃO AUTORIZADO: " + ipOrigem);
                    System.err.println("   → Apenas a Borda pode enviar dados para esta porta.");
                    System.err.println("   → IPs Permitidos: " + IPS_BORDA_PERMITIDOS);
                    clientSocket.close();
                    
                    // Log de tentativa de intrusão
                    logTentativaIntrusao(ipOrigem, TCP_PORT, "Ingestão de Dados");
                    continue;
                }
                
                System.out.println("✅ FW2 PERMITIDO: Conexão da Borda aceita (IP: " + ipOrigem + ")");
                new Thread(() -> handleBordaConnection(clientSocket, ipOrigem)).start();
            }
        } catch (IOException e) {
            System.err.println("❌ Erro no listener da Borda: " + e.getMessage());
        }
    }

    private static void startClientListener() {
        try (ServerSocket clientServerSocket = new ServerSocket(CLIENT_PORT)) {
            System.out.println("🌐 Listener de Consulta ATIVO na porta TCP " + CLIENT_PORT + " (Aguardando Clientes)...\n");
            
            while (true) {
                Socket clientSocket = clientServerSocket.accept();
                String ipCliente = clientSocket.getInetAddress().getHostAddress();
                System.out.println("📞 Nova requisição de consulta do Cliente (IP: " + ipCliente + ")");
                
                new Thread(() -> handleClientRequest(clientSocket, ipCliente)).start();
            }
        } catch (IOException e) {
            System.err.println("❌ Erro no listener do Cliente: " + e.getMessage());
        }
    }

    private static void handleBordaConnection(Socket socket, String ipOrigem) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            // Descriptografia Híbrida (Borda -> Datacenter)
            MensagemCriptografada msg = (MensagemCriptografada) ois.readObject();
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // Validação adicional dos dados
            if (dados.getDispositivoId() == null || dados.getDispositivoId().isEmpty()) {
                System.err.println("⚠️  Dados inválidos recebidos da Borda (ID vazio). Descartando.");
                return;
            }
            
            // Armazena e Persiste
            synchronized (dadosHistoricos) {
                dadosHistoricos.add(dados);
            }
            saveDataToDatabase(dados);
            
            System.out.println("💾 Datacenter armazenou dados de: " + dados.getDispositivoId() + 
                             " | Temp: " + String.format("%.1f°C", dados.getTemperatura()) + 
                             " | CO2: " + String.format("%.0f ppm", dados.getCo2()) +
                             " | Total: " + dadosHistoricos.size() + " registros");
            
        } catch (ClassNotFoundException e) {
            System.err.println("⚠️  Datacenter: Classe não encontrada na deserialização: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("⚠️  Datacenter: Erro ao processar dados da Borda (IP: " + ipOrigem + "): " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }
    
    private static void handleClientRequest(Socket socket, String ipCliente) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            System.out.println("📥 Processando requisição do Cliente (IP: " + ipCliente + ")...");
            
            // 1. Recebe a requisição criptografada (contém a chave AES de sessão)
            MensagemCriptografada reqCriptografada = (MensagemCriptografada) ois.readObject();

            // 2. Descriptografa para obter a chave AES do Cliente
            SecretKey aesKeyCliente = CriptografiaHibrida.decryptAESKeyWithRSA(
                reqCriptografada.getChaveSimetricaCriptografada(), rsaPrivateKey);
            
            // 3. Valida a requisição (opcional - pode descriptografar o payload para validar)
            byte[] reqDecrypted = CriptografiaHibrida.decryptAES(
                reqCriptografada.getDadosCriptografados(), aesKeyCliente);
            MensagemLogin requisicao = (MensagemLogin) CriptografiaHibrida.deserialize(reqDecrypted);
            
            System.out.println("   → Cliente identificado: " + requisicao.getId());
            System.out.println("   → Tipo de consulta: " + requisicao.getTipoServico());
            
            // 4. Prepara a lista de dados históricos
            List<DadosColetados> dadosParaEnviar;
            synchronized (dadosHistoricos) {
                dadosParaEnviar = new ArrayList<>(dadosHistoricos);
            }
            
            // 5. Serializa a lista de dados
            byte[] dadosSerializados = CriptografiaHibrida.serialize((Serializable) dadosParaEnviar);

            // 6. Criptografa os dados com a chave AES obtida na requisição
            byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKeyCliente);

            // 7. Envia a resposta criptografada (reutilizando a chave AES de sessão)
            MensagemCriptografada respostaCriptografada = new MensagemCriptografada(
                new byte[0], // Chave RSA vazia (não precisa reenviar)
                dadosCriptografados
            );

            oos.writeObject(respostaCriptografada);
            oos.flush();
            
            System.out.println("📤 Datacenter enviou " + dadosParaEnviar.size() + 
                             " registros CRIPTOGRAFADOS ao Cliente " + requisicao.getId() + 
                             " (IP: " + ipCliente + ")");
            System.out.println("   → Tamanho dos dados criptografados: " + dadosCriptografados.length + " bytes\n");
            
        } catch (ClassNotFoundException e) {
            System.err.println("⚠️  Erro: Classe não encontrada ao processar requisição do Cliente.");
        } catch (Exception e) {
            System.err.println("⚠️  Datacenter: Erro ao atender Cliente (IP: " + ipCliente + "): " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }

    // ===== MÉTODOS DE PERSISTÊNCIA =====
    
    private static void saveDataToDatabase(DadosColetados dados) {
        try {
            // Verifica se o arquivo existe para decidir se cria novo header
            boolean arquivoExiste = new File(DATABASE_FILE).exists() && new File(DATABASE_FILE).length() > 0;
            
            try (FileOutputStream fos = new FileOutputStream(DATABASE_FILE, true);
                 ObjectOutputStream oos = arquivoExiste ? 
                     new ObjectOutputStream(fos) {
                         @Override
                         protected void writeStreamHeader() throws IOException {
                             // Suprime o header para append
                             reset();
                         }
                     } : new ObjectOutputStream(fos))
            {
                oos.writeObject(dados);
                oos.flush();
            }
        } catch (IOException e) {
            System.err.println("⚠️  Erro ao persistir dados no arquivo: " + e.getMessage());
        }
    }
    
    private static void loadDataFromDatabase() {
        File file = new File(DATABASE_FILE);
        if (!file.exists() || file.length() == 0) {
            System.out.println("ℹ️  Nenhum dado histórico encontrado. Iniciando com base vazia.");
            return;
        }

        int count = 0;
        try (FileInputStream fis = new FileInputStream(file);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            
            while (true) {
                try {
                    DadosColetados dados = (DadosColetados) ois.readObject();
                    dadosHistoricos.add(dados);
                    count++;
                } catch (EOFException e) {
                    // Fim do arquivo alcançado
                    break;
                } catch (ClassNotFoundException e) {
                    System.err.println("⚠️  Classe não encontrada ao carregar registro " + (count + 1));
                    break;
                } catch (IOException e) {
                    System.err.println("⚠️  Erro de I/O ao carregar registro " + (count + 1) + ": " + e.getMessage());
                    break;
                }
            }
            
            System.out.println("✅ " + count + " registros carregados com sucesso do banco de dados.");
            
        } catch (IOException e) {
            System.err.println("⚠️  Erro ao abrir arquivo de banco de dados: " + e.getMessage());
        }
    }
    
    // ===== LOG DE SEGURANÇA =====
    
    private static void logTentativaIntrusao(String ip, int porta, String servico) {
        String logEntry = String.format(
            "[%s] 🚨 TENTATIVA DE INTRUSÃO - IP: %s | Porta: %d | Serviço: %s | Ação: BLOQUEADO",
            java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
            ip, porta, servico
        );
        
        // Em produção, isso seria salvo em arquivo de log de segurança
        System.err.println(logEntry);
        
        // Opcional: Salvar em arquivo de log
        try (FileWriter fw = new FileWriter("datacenter_security.log", true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
        } catch (IOException e) {
            System.err.println("Erro ao salvar log de segurança: " + e.getMessage());
        }
    }
}