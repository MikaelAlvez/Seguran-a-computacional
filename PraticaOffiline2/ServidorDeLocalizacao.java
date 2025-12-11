package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

// Classe auxiliar LocalizacaoResponse (Definida aqui para resolver o erro de compilação)
class LocalizacaoResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    private final boolean autenticado;
    private final String enderecoServico;
    private final int portaServico;

    public LocalizacaoResponse(boolean autenticado, String enderecoServico, int portaServico) {
        this.autenticado = autenticado;
        this.enderecoServico = enderecoServico;
        this.portaServico = portaServico;
    }

    public boolean isAutenticado() { return autenticado; }
    public String getEnderecoServico() { return enderecoServico; }
    public int getPortaServico() { return portaServico; }
}

public class ServidorDeLocalizacao {
    public static final int LOC_PORT = 6666;
    public static final String SERVER_IP = "127.0.0.1";
    public static final String LOC_PUB_KEY_FILE = "loc.pub";
    
    private static PrivateKey rsaPrivateKey;

    public static void main(String[] args) {
        System.out.println("--- SERVIDOR DE LOCALIZAÇÃO INICIADO ---");
        try {
            // Geração de Chaves RSA da Localização
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, LOC_PUB_KEY_FILE);
            
            System.out.println("Localização: Chaves RSA geradas e 'loc.pub' salvo.");
            
            ExecutorService executor = Executors.newCachedThreadPool();

            try (ServerSocket serverSocket = new ServerSocket(LOC_PORT)) {
                System.out.println("Aguardando requisições na porta TCP " + LOC_PORT + "...");
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    executor.submit(() -> handleConnection(clientSocket));
                }
            }
        } catch (Exception e) {
            System.err.println("Erro fatal no Servidor de Localização: " + e.getMessage());
        }
    }

    private static void handleConnection(Socket socket) {
        String id = "DESCONHECIDO";
        LocalizacaoResponse response;

        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

            // 1. RECEBIMENTO E DESCRIPTOGRAFIA HÍBRIDA
            // Assumimos que MensagemCriptografada e MensagemLogin estão disponíveis no pacote PraticaOffiline2
            MensagemCriptografada msgEntrada = (MensagemCriptografada) ois.readObject();
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msgEntrada.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedLoginData = CriptografiaHibrida.decryptAES(
                msgEntrada.getDadosCriptografados(), aesKey);
            
            MensagemLogin requisicao = (MensagemLogin) CriptografiaHibrida.deserialize(decryptedLoginData);
            
            id = requisicao.getId();
            String tipoServico = requisicao.getTipoServico(); 

            // 2. LÓGICA DE LOCALIZAÇÃO
            if (tipoServico.equals("BORDA")) {
                // A porta da Borda é para UDP
                response = new LocalizacaoResponse(true, SERVER_IP, ServidorBorda.UDP_PORT);
                System.out.println("📍 Localização OK: " + id + ". Redirecionado para Borda.");
            } else if (tipoServico.equals("DATACENTER")) {
                // A porta do Datacenter é para consulta TCP do Cliente
                response = new LocalizacaoResponse(true, SERVER_IP, ServidorDatacenter.CLIENT_PORT); 
                System.out.println("📍 Localização OK: " + id + ". Redirecionado para Datacenter.");
            } else {
                response = new LocalizacaoResponse(false, null, 0); 
            }
            
            // 3. CRIPTOGRAFIA E ENVIO DA RESPOSTA HÍBRIDA
            byte[] responseSerializada = CriptografiaHibrida.serialize(response);
            byte[] responseCriptografada = CriptografiaHibrida.encryptAES(responseSerializada, aesKey);
            
            // Empacota a resposta
            MensagemCriptografada msgSaida = new MensagemCriptografada(
                new byte[0], // Não precisamos enviar a chave RSA de volta
                responseCriptografada
            );
            
            oos.writeObject(msgSaida);
            oos.flush();

        } catch (Exception e) {
            System.err.println("Erro no tratamento da conexão de localização para ID " + id + ": " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignorar */ }
        }
    }
}