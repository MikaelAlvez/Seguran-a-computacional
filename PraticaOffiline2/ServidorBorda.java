package PraticaOffiline2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;

public class ServidorBorda {
    public static final String SERVER_IP = "127.0.0.1";
    public static final int UDP_PORT = 5555; 
    public static final int CONTROL_PORT = 5556; // Porta TCP de controle
    
    private static final String DATACENTER_IP = "127.0.0.1";
    public static final int DATACENTER_TCP_PORT = 8888; 
    
    public static final String BORDA_PUB_KEY_FILE = "borda.pub";
    
    private static PrivateKey rsaPrivateKey;
    private static PublicKey datacenterPublicKey; 
    
    // Lista de dispositivos bloqueados pelo IDS/IPS
    private static final Set<String> dispositivosBloqueados = ConcurrentHashMap.newKeySet();
    
    // Simulação do Cache
    private static final int CACHE_SIZE = 50;
    private static final List<DadosColetados> cache = Collections.synchronizedList(new LinkedList<>());

    public static void main(String[] args) {
        System.out.println("--- BORDA INICIADA ---");
        try {
            // Geração das Chaves RSA da Borda
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, BORDA_PUB_KEY_FILE);

            // Carrega a Chave Pública do Datacenter
            datacenterPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDatacenter.DATACENTER_PUB_KEY_FILE);

            System.out.println("Borda: Chaves RSA geradas/carregadas.");
            System.out.println("Aguardando Dispositivos na porta UDP " + UDP_PORT + "...");
            System.out.println("Porta de Controle IDS/IPS ativa na TCP " + CONTROL_PORT + "...");
            
            // Inicia o listener UDP em thread separada
            new Thread(() -> {
                try {
                    startUDPListener();
                } catch (IOException e) {
                    System.err.println("Erro no listener UDP: " + e.getMessage());
                }
            }).start();
            
            // Inicia o listener TCP de controle (para comandos do IDS/IPS)
            startControlListener();
            
        } catch (Exception e) {
            System.err.println("Erro fatal na Borda: " + e.getMessage());
        }
    }

    private static void startUDPListener() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(UDP_PORT)) {
            byte[] buffer = new byte[1024 * 10]; 
            
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                new Thread(() -> processUDPPacket(packet)).start();
            }
        }
    }
    
    private static void startControlListener() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(CONTROL_PORT)) {
            System.out.println("✅ Listener de Controle IDS/IPS ativo na porta " + CONTROL_PORT);
            
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> handleControlCommand(socket)).start();
            }
        }
    }
    
    private static void handleControlCommand(Socket socket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            String comando = in.readLine();
            
            if (comando != null && comando.startsWith("DROP:")) {
                String dispositivoId = comando.substring(5);
                dispositivosBloqueados.add(dispositivoId);
                System.out.println("🔒 FW1/BORDA: Dispositivo " + dispositivoId + " BLOQUEADO por ordem do IDS/IPS.");
            }
            
        } catch (IOException e) {
            System.err.println("Erro no comando de controle: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }
    
    private static void processUDPPacket(DatagramPacket packet) {
        try {
            String ipOrigem = packet.getAddress().getHostAddress();
            
            // Descriptografia Híbrida (UDP)
            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());
            MensagemCriptografada msg = (MensagemCriptografada) CriptografiaHibrida.deserialize(data);
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // FIREWALL FW1: Verifica se dispositivo está bloqueado
            if (dispositivosBloqueados.contains(dados.getDispositivoId())) {
                System.err.println("🚫 FW1: PACOTE BLOQUEADO de " + dados.getDispositivoId() + " (bloqueado pelo IPS).");
                return;
            }
            
            // Autenticação e Verificação de Dispositivo Inválido
            if (dados.getDispositivoId().startsWith("DI_")) {
                System.err.println("⚠️ BORDA: PACOTE REJEITADO! Dispositivo Inválido (" + dados.getDispositivoId() + ").");
                // Envia alerta ao IDS
                SistemaIDS.sendAlert(dados, ipOrigem, aesKey);
                return;
            }
            
            // Análise Rápida e envio ao IDS para monitoramento
            SistemaIDS.sendAlert(dados, ipOrigem, aesKey);
            
            // Alerta local da borda (mantido para comparação)
            if (dados.getTemperatura() > 39.0) {
                System.out.println("🚨 BORDA ALERTA RÁPIDO: Dispositivo " + dados.getDispositivoId() + " detectou TEMP ELEVADA (>" + dados.getTemperatura() + "°C).");
            }

            // Implementação do Cache
            addToCache(dados);

            // Envio ao Datacenter (TCP Criptografado)
            forwardToDatacenter(dados);
            
        } catch (Exception e) {
            System.err.println("Borda: Erro de descriptografia/processamento. " + e.getMessage());
        }
    }

    private static void addToCache(DadosColetados dados) {
        cache.add(dados);
        if (cache.size() > CACHE_SIZE) {
            cache.remove(0); 
        }
    }

    private static void forwardToDatacenter(DadosColetados dados) {
        try (Socket socket = new Socket(DATACENTER_IP, DATACENTER_TCP_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // Re-criptografia para o Datacenter
            byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
            SecretKey aesKey = CriptografiaHibrida.generateAESKey();
            byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
            byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, datacenterPublicKey);
            
            MensagemCriptografada msgDatacenter = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);

            oos.writeObject(msgDatacenter);
            oos.flush();
            System.out.println("Borda: Dados de " + dados.getDispositivoId() + " encaminhados ao Datacenter.");
            
        } catch (ConnectException e) {
            System.err.println("Borda: ERRO DE CONEXÃO. Datacenter não está rodando na porta " + DATACENTER_TCP_PORT + ".");
        } catch (Exception e) {
            System.err.println("Borda: Erro ao encaminhar dados via TCP: " + e.getMessage());
        }
    }
}