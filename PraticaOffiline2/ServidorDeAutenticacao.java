package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

// Classe auxiliar para resposta de autenticação
class AutenticacaoResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    private final boolean autenticado;
    private final String mensagem; 

    public AutenticacaoResponse(boolean autenticado, String mensagem) {
        this.autenticado = autenticado;
        this.mensagem = mensagem;
    }

    public boolean isAutenticado() { return autenticado; }
    public String getMensagem() { return mensagem; }
}

public class ServidorDeAutenticacao {
    public static final int AUTH_PORT = 7777;
    public static final String SERVER_IP = "127.0.0.1";
    public static final String AUTH_PUB_KEY_FILE = "auth.pub";
    
    private static PrivateKey rsaPrivateKey;

    private static final Map<String, String> CREDENCIAIS = new HashMap<>();
    static {
        CREDENCIAIS.put("D1_Correto", "keyD1");
        CREDENCIAIS.put("D2_Correto", "keyD2");
        CREDENCIAIS.put("D3_Correto", "keyD3");
        CREDENCIAIS.put("D4_Correto", "keyD4");
        CREDENCIAIS.put("Gestor_Urbano", "keyGU"); 
    }

    public static void main(String[] args) {
        System.out.println("--- SERVIDOR DE AUTENTICAÇÃO INICIADO ---");
        try {
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, AUTH_PUB_KEY_FILE);
            
            System.out.println("Autenticação: Chaves RSA geradas e 'auth.pub' salvo.");
            
            ExecutorService executor = Executors.newCachedThreadPool();

            try (ServerSocket serverSocket = new ServerSocket(AUTH_PORT)) {
                System.out.println("Aguardando requisições na porta TCP " + AUTH_PORT + "...");
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    executor.submit(() -> handleConnection(clientSocket));
                }
            }
        } catch (Exception e) {
            System.err.println("Erro fatal no Servidor de Autenticação: " + e.getMessage());
        }
    }

    private static void handleConnection(Socket socket) {
        String id = "DESCONHECIDO";
        AutenticacaoResponse response;

        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

            // 1. RECEBIMENTO E DESCRIPTOGRAFIA HÍBRIDA (Cliente/Dispositivo -> Autenticação)
            MensagemCriptografada msgEntrada = (MensagemCriptografada) ois.readObject();
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msgEntrada.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedLoginData = CriptografiaHibrida.decryptAES(
                msgEntrada.getDadosCriptografados(), aesKey);
            
            MensagemLogin login = (MensagemLogin) CriptografiaHibrida.deserialize(decryptedLoginData);
            
            id = login.getId();
            String token = login.getToken(); 

            // 2. AUTENTICAÇÃO
            boolean autenticado = CREDENCIAIS.containsKey(id) && CREDENCIAIS.get(id).equals(token);

            if (autenticado) {
                response = new AutenticacaoResponse(true, "Bem-vindo, " + id);
                System.out.println("✅ Autenticação OK: " + id);
            } else {
                response = new AutenticacaoResponse(false, "Credenciais Inválidas.");
                System.out.println("❌ Autenticação FALHOU: ID " + id);
            }
            
            // 3. CRIPTOGRAFIA E ENVIO DA RESPOSTA HÍBRIDA
            byte[] responseSerializada = CriptografiaHibrida.serialize(response);
            byte[] responseCriptografada = CriptografiaHibrida.encryptAES(responseSerializada, aesKey);
            
            MensagemCriptografada msgSaida = new MensagemCriptografada(
                new byte[0], 
                responseCriptografada
            );
            
            oos.writeObject(msgSaida);
            oos.flush();

        } catch (Exception e) {
            System.err.println("Erro no tratamento da conexão de autenticação para ID " + id + ": " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }
}