package PraticaOffiline2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

public class ServidorDatacenter {
    // Porta para a Borda (Ingestão de dados)
    public static final int TCP_PORT = 8888; 
    // Porta para o Cliente Gestor_Urbano (Consulta de dados)
    public static final int CLIENT_PORT = 8080; 
    
    public static final String DATACENTER_PUB_KEY_FILE = "datacenter.pub";
    
    private static PrivateKey rsaPrivateKey; 
    // Lista thread-safe para armazenar os dados recebidos
    private static final List<DadosColetados> dadosHistoricos = Collections.synchronizedList(new LinkedList<>()); 
    
    public static void main(String[] args) {
        try {
            // Geração e Salvamento da Chave Pública RSA
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, DATACENTER_PUB_KEY_FILE);

            System.out.println("--- DATACENTER INICIADO ---");
            
            // Inicializa o serviço para executar múltiplos listeners concorrentemente
            ExecutorService executor = Executors.newFixedThreadPool(2);
            
            // Inicia o listener para receber dados da Borda (Porta 8888)
            executor.submit(ServidorDatacenter::startBordaListener);
            
            // Inicia o listener para atender requisições de consulta do Cliente (Porta 8080)
            executor.submit(ServidorDatacenter::startClientListener);
            
        } catch (Exception e) {
            System.err.println("Erro fatal no Datacenter: " + e.getMessage());
        }
    }
    
    // Listener dedicado a receber dados da Borda (Ingestão)
    private static void startBordaListener() {
        try (ServerSocket serverSocket = new ServerSocket(TCP_PORT)) {
            System.out.println("Aguardando dados da Borda na porta TCP " + TCP_PORT + "...");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleBordaConnection(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Erro no listener da Borda: " + e.getMessage());
        }
    }

    // Listener dedicado a atender requisições de consulta do Cliente
    private static void startClientListener() {
        try (ServerSocket clientServerSocket = new ServerSocket(CLIENT_PORT)) {
            System.out.println("Aguardando requisições do Cliente na porta TCP " + CLIENT_PORT + "...");
            while (true) {
                Socket clientSocket = clientServerSocket.accept();
                // Atende a requisição em uma nova thread
                new Thread(() -> handleClientRequest(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Erro no listener do Cliente: " + e.getMessage());
        }
    }

    // Processa a conexão da Borda (Recebimento de dados)
    private static void handleBordaConnection(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            MensagemCriptografada msg = (MensagemCriptografada) ois.readObject();
            
            // Descriptografar a chave AES com a chave PRIVADA do Datacenter
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            
            // Descriptografar os Dados com a chave AES
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            
            // Deserializar para obter os Dados Coletados
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // Armazena os dados
            dadosHistoricos.add(dados);
            System.out.println("Datacenter recebeu e armazenou: " + dados.toString());
            
        } catch (Exception e) {
            System.err.println("Datacenter: Erro de descriptografia/armazenamento. Pacote da Borda Descartado. " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) {
            	
            }
        }
    }
    
    // Processa a conexão do Cliente (Consulta de dados)
    private static void handleClientRequest(Socket socket) {
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // Envia toda a lista de DadosColetados serializada
            oos.writeObject(dadosHistoricos);
            oos.flush();
            System.out.println("Datacenter enviou " + dadosHistoricos.size() + " dados históricos ao Cliente Gestor_Urbano.");
            
        } catch (Exception e) {
            System.err.println("Datacenter: Erro ao atender requisição do Cliente. " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { 
            	
            }
        }
    }

    public static List<DadosColetados> getDadosHistoricos() {
        return dadosHistoricos;
    }
}