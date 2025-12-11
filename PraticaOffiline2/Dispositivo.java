package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class Dispositivo {
    public static final String BORDA_PUB_KEY_FILE = "borda.pub"; 
    private static final int TEMPO_TOTAL_SEGUNDOS = 300; 
    private static final int REPETICOES_TOTAIS = (int) Math.ceil(TEMPO_TOTAL_SEGUNDOS / 2.5); 

    private final String dispositivoId;
    private final String token; 
    
    // Chaves públicas necessárias
    private static PublicKey bordaPublicKey;
    private static PublicKey authPublicKey; 
    private static PublicKey locPublicKey;  
    
    private final Random random = new Random();

    public Dispositivo(String id, String token) { 
        this.dispositivoId = id;
        this.token = token;
    }

    public static void main(String[] args) throws Exception {
        
        System.out.println("--- CLIENTE DISPOSITIVO INICIADO ---");
        
        // 1. CARREGAMENTO DAS CHAVES PÚBLICAS
        try {
            bordaPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(BORDA_PUB_KEY_FILE);
            authPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
            locPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeLocalizacao.LOC_PUB_KEY_FILE); 
            System.out.println("Dispositivo: Chaves públicas carregadas com sucesso (Borda, Auth, Loc).");
        } catch (Exception e) {
            System.err.println("ERRO: Não foi possível carregar todas as chaves públicas. Certifique-se que os Servidores foram inicializados primeiro. " + e.getMessage());
            return;
        }

        // 2. SIMULAÇÃO E INICIALIZAÇÃO DE THREADS
        Dispositivo d1 = new Dispositivo("D1_Correto", "keyD1");
        Dispositivo d2 = new Dispositivo("D2_Correto", "keyD2");
        Dispositivo d3 = new Dispositivo("D3_Correto", "keyD3");
        Dispositivo d4 = new Dispositivo("D4_Correto", "keyD4");
        Dispositivo d_invalido = new Dispositivo("DI_Invalido", "token_errado"); 

        new Thread(() -> d1.iniciarColeta()).start();
        new Thread(() -> d2.iniciarColeta()).start();
        new Thread(() -> d3.iniciarColeta()).start();
        new Thread(() -> d4.iniciarColeta()).start();
        new Thread(() -> d_invalido.iniciarColeta()).start();
        
        System.out.println("\nSIMULAÇÃO: Dispositivos tentarão Autenticar, Localizar e Enviar dados.");
    }

    private void iniciarColeta() {
        
        // FASE 1: AUTENTICAÇÃO (TCP Híbrido)
        AutenticacaoResponse authResponse = solicitarAutenticacao(dispositivoId, token, authPublicKey);

        if (authResponse == null || !authResponse.isAutenticado()) {
            System.err.println("Dispositivo " + dispositivoId + ": Autenticação falhou. Encerrando.");
            return;
        }
        System.out.println("Dispositivo " + dispositivoId + ": " + authResponse.getMensagem());

        // FASE 2: LOCALIZAÇÃO (TCP Híbrido)
        LocalizacaoResponse locResponse = solicitarLocalizacao(dispositivoId, "BORDA", locPublicKey);

        if (locResponse == null || !locResponse.isAutenticado()) {
            System.err.println("Dispositivo " + dispositivoId + ": Localização indisponível. Encerrando.");
            return;
        }

        String bordaIp = locResponse.getEnderecoServico();
        int bordaPort = locResponse.getPortaServico();

        System.out.println("Dispositivo " + dispositivoId + " localizado. Envio para Borda em " + bordaIp + ":" + bordaPort + ".");
        
        // FASE 3: CICLO DE COLETA E ENVIO (UDP Híbrido)
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName(bordaIp);

            for (int i = 1; i <= REPETICOES_TOTAIS; i++) {
                
                DadosColetados dados = new DadosColetados(dispositivoId);
                byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
                
                SecretKey aesKey = CriptografiaHibrida.generateAESKey();
                byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
                
                byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, bordaPublicKey);
                
                MensagemCriptografada mensagem = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);
                byte[] mensagemBytes = CriptografiaHibrida.serialize(mensagem);

                DatagramPacket packet = new DatagramPacket(mensagemBytes, mensagemBytes.length, address, bordaPort);
                socket.send(packet);
                
                System.out.println("Dispositivo " + dispositivoId + ": Envio " + i + "/" + REPETICOES_TOTAIS + " via UDP (Híbrido) para Borda.");
                
                long sleepTime = 2000 + random.nextInt(1000); 
                TimeUnit.MILLISECONDS.sleep(sleepTime);
            }
            
            System.out.println("Dispositivo " + dispositivoId + ": FINALIZOU a coleta de dados.");
            
        } catch (Exception e) {
            System.err.println("Dispositivo " + dispositivoId + ": Erro durante o ciclo de envio. " + e.getMessage());
        }
    }
    
    // --- MÉTODOS DE COMUNICAÇÃO HÍBRIDA (NOVA ARQUITETURA) ---

    private AutenticacaoResponse solicitarAutenticacao(String id, String token, PublicKey authPublicKey) {
        try (Socket socket = new Socket(ServidorDeAutenticacao.SERVER_IP, ServidorDeAutenticacao.AUTH_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            MensagemLogin login = new MensagemLogin(id, token, null); 
            SecretKey aesKey = enviarRequisicaoHibrida(oos, login, authPublicKey);

            return (AutenticacaoResponse) receberRespostaHibrida(ois, aesKey);

        } catch (ConnectException e) {
            System.err.println("Dispositivo " + id + ": Falha ao conectar ao Servidor de Autenticação.");
            return null;
        } catch (Exception e) {
            // Este catch pega o erro de ClassCastException no Servidor (se ele acontecer)
            System.err.println("Dispositivo " + id + ": Erro no processo de Autenticação. " + e.getMessage());
            return null;
        }
    }

    private LocalizacaoResponse solicitarLocalizacao(String id, String tipoServico, PublicKey locPublicKey) {
         try (Socket socket = new Socket(ServidorDeLocalizacao.SERVER_IP, ServidorDeLocalizacao.LOC_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            MensagemLogin requisicao = new MensagemLogin(id, null, tipoServico);
            SecretKey aesKey = enviarRequisicaoHibrida(oos, requisicao, locPublicKey);

            return (LocalizacaoResponse) receberRespostaHibrida(ois, aesKey);

        } catch (ConnectException e) {
            System.err.println("Dispositivo " + id + ": Falha ao conectar ao Servidor de Localização.");
            return null;
        } catch (Exception e) {
            System.err.println("Dispositivo " + id + ": Erro no processo de Localização. " + e.getMessage());
            return null;
        }
    }
    
    // Método reutilizável para enviar a requisição inicial (AES + Chave RSA)
    private SecretKey enviarRequisicaoHibrida(ObjectOutputStream oos, Serializable payload, PublicKey serverPublicKey) throws Exception {
        byte[] payloadSerializado = CriptografiaHibrida.serialize(payload);
        
        SecretKey aesKey = CriptografiaHibrida.generateAESKey();
        byte[] payloadCriptografado = CriptografiaHibrida.encryptAES(payloadSerializado, aesKey);
        
        byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, serverPublicKey);
        
        MensagemCriptografada msgRequisicao = new MensagemCriptografada(chaveAESCriptografada, payloadCriptografado);
        oos.writeObject(msgRequisicao);
        oos.flush();
        
        return aesKey;
    }

    // Método reutilizável para receber e descriptografar a resposta (apenas AES)
    private Object receberRespostaHibrida(ObjectInputStream ois, SecretKey aesKey) throws Exception {
        MensagemCriptografada msgResposta = (MensagemCriptografada) ois.readObject();
        
        byte[] responseCriptografada = msgResposta.getDadosCriptografados();
        byte[] responseDecrypted = CriptografiaHibrida.decryptAES(responseCriptografada, aesKey);
        
        return CriptografiaHibrida.deserialize(responseDecrypted);
    }
}