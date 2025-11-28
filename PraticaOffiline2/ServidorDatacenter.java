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
    public static final int TCP_PORT = 8888; 
    public static final int CLIENT_PORT = 8080; 
    
    public static final String DATACENTER_PUB_KEY_FILE = "datacenter.pub";
    // Simulação da Base de Dados
    public static final String DATABASE_FILE = "datacenter_db.txt"; 
    
    private static PrivateKey rsaPrivateKey; 
    private static final List<DadosColetados> dadosHistoricos = Collections.synchronizedList(new LinkedList<>()); 
    
    public static void main(String[] args) {
        try {
            // Geração e Salvamento da Chave Pública RSA
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, DATACENTER_PUB_KEY_FILE);

            // Carrega dados de sessões anteriores
            loadDataFromDatabase();

            System.out.println("--- DATACENTER INICIADO ---");
            System.out.println("Carregados " + dadosHistoricos.size() + " registros do banco de dados.");
            
            ExecutorService executor = Executors.newFixedThreadPool(2);
            
            executor.submit(ServidorDatacenter::startBordaListener);
            executor.submit(ServidorDatacenter::startClientListener);
            
        } catch (Exception e) {
            System.err.println("Erro fatal no Datacenter: " + e.getMessage());
        }
    }
    
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

    private static void startClientListener() {
        try (ServerSocket clientServerSocket = new ServerSocket(CLIENT_PORT)) {
            System.out.println("Aguardando requisições do Cliente na porta TCP " + CLIENT_PORT + "...");
            while (true) {
                Socket clientSocket = clientServerSocket.accept();
                new Thread(() -> handleClientRequest(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Erro no listener do Cliente: " + e.getMessage());
        }
    }

    private static void handleBordaConnection(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            // Descriptografia Híbrida (Borda -> Datacenter)
            MensagemCriptografada msg = (MensagemCriptografada) ois.readObject();
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // Armazena e Persiste
            dadosHistoricos.add(dados);
            saveDataToDatabase(dados); 
            System.out.println("Datacenter recebeu e armazenou: " + dados.getDispositivoId());
            
        } catch (Exception e) {
            System.err.println("Datacenter: Erro de descriptografia/armazenamento. Pacote da Borda Descartado. " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }
    
    private static void handleClientRequest(Socket socket) {
        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // Envia todos os dados
            oos.writeObject(dadosHistoricos);
            oos.flush();
            System.out.println("Datacenter enviou " + dadosHistoricos.size() + " dados históricos ao Cliente Gestor_Urbano.");
            
        } catch (Exception e) {
            System.err.println("Datacenter: Erro ao atender requisição do Cliente. " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }

    // Simulação de Banco de Dados Escalável (Persistência em Arquivo)

    private static void saveDataToDatabase(DadosColetados dados) {
        try (FileOutputStream fos = new FileOutputStream(DATABASE_FILE, true); 
             ObjectOutputStream oos = new ObjectOutputStream(fos) {
                 protected void writeStreamHeader() throws IOException {} 
             }) 
        {
            oos.writeObject(dados);
        } catch (IOException e) {
            System.err.println("Erro ao persistir dados: " + e.getMessage());
        }
    }
    
    private static void loadDataFromDatabase() {
        File file = new File(DATABASE_FILE);
        if (!file.exists() || file.length() == 0) {
            return;
        }

        try (FileInputStream fis = new FileInputStream(file);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            
            while (true) {
                try {
                    DadosColetados dados = (DadosColetados) ois.readObject();
                    dadosHistoricos.add(dados);
                } catch (EOFException e) {
                    break; 
                } catch (ClassNotFoundException | IOException e) {
                    System.err.println("Erro durante o carregamento do DB: " + e.getMessage());
                    break;
                }
            }
        } catch (IOException e) {

        }
    }
}