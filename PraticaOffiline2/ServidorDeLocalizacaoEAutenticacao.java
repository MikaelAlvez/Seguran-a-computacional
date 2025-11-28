package PraticaOffiline2;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// Classe auxiliar para a resposta de localização
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

public class ServidorDeLocalizacaoEAutenticacao {
    public static final int LOCALIZACAO_PORT = 7777;
    public static final String SERVER_IP = "127.0.0.1";

    // Simulação de credenciais válidas: ID -> Chave (Token)
    private static final Map<String, String> CREDENCIAIS = new HashMap<>();
    static {
        // Dispositivos (D4 foi adicionado para cumprir o requisito de 4)
        CREDENCIAIS.put("D1_Correto", "keyD1");
        CREDENCIAIS.put("D2_Correto", "keyD2");
        CREDENCIAIS.put("D3_Correto", "keyD3");
        CREDENCIAIS.put("D4_Correto", "keyD4");
        // Cliente
        CREDENCIAIS.put("Gestor_Urbano", "keyGU"); 
    }

    public static void main(String[] args) {
        System.out.println("--- SERVIDOR DE LOCALIZAÇÃO & AUTENTICAÇÃO INICIADO ---");
        ExecutorService executor = Executors.newCachedThreadPool();

        try (ServerSocket serverSocket = new ServerSocket(LOCALIZACAO_PORT)) {
            System.out.println("Aguardando conexões (Descoberta/Autenticação) na porta TCP " + LOCALIZACAO_PORT + "...");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleConnection(clientSocket));
            }
        } catch (IOException e) {
            System.err.println("Erro no Servidor de Localização: " + e.getMessage());
        }
    }

    private static void handleConnection(Socket socket) {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

            String id = (String) ois.readObject();
            String token = (String) ois.readObject();
            String tipoServico = (String) ois.readObject(); // "BORDA" ou "DATACENTER"

            LocalizacaoResponse response;
            // 2. Autenticação: Verifica se o ID existe e se o token é correto
            boolean autenticado = CREDENCIAIS.containsKey(id) && CREDENCIAIS.get(id).equals(token);

            if (autenticado) {
                if (tipoServico.equals("BORDA")) {
                    // Redireciona Dispositivo para a Borda (Porta UDP 5555)
                    response = new LocalizacaoResponse(true, ServidorDeLocalizacaoEAutenticacao.SERVER_IP, ServidorBorda.UDP_PORT);
                    System.out.println("✅ Autenticação OK: " + id + ". Redirecionado para Borda.");
                } else if (tipoServico.equals("DATACENTER")) {
                    // Redireciona Cliente para o Datacenter (Porta TCP 8080)
                    response = new LocalizacaoResponse(true, ServidorDeLocalizacaoEAutenticacao.SERVER_IP, ServidorDatacenter.CLIENT_PORT);
                    System.out.println("✅ Autenticação OK: " + id + ". Redirecionado para Datacenter.");
                } else {
                    response = new LocalizacaoResponse(false, null, 0);
                }
            } else {
                response = new LocalizacaoResponse(false, null, 0);
                System.out.println("❌ Autenticação FALHOU: ID " + id + " (Token inválido).");
            }

            oos.writeObject(response);
            oos.flush();

        } catch (Exception e) {
            System.err.println("Erro no tratamento da conexão de localização: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException e) { /* ignore */ }
        }
    }
}