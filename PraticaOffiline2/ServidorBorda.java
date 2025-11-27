package PraticaOffiline2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class ServidorBorda {
    // Porta UDP para receber dados dos Dispositivos
    public static final int UDP_PORT = 5555; 
    
    // Porta TCP para enviar dados ao Datacenter (assumindo a porta 8888 do Datacenter)
    private static final String DATACENTER_IP = "127.0.0.1";
    public static final int DATACENTER_TCP_PORT = 8888; 
    
    public static final String BORDA_PUB_KEY_FILE = "borda.pub";
    public static final String BORDA_PRIV_KEY_FILE = "borda.priv";
    
    private static PrivateKey rsaPrivateKey;
    private static PublicKey datacenterPublicKey; // Criptografia Borda -> Datacenter (TCP)

    public static void main(String[] args) {
        System.out.println("--- BORDA INICIADA ---");
        try {
            // Geração e Salvamento das Chaves RSA da Borda
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, BORDA_PUB_KEY_FILE);
            // CriptografiaHibrida.savePrivateKeyToFile(rsaPrivateKey, BORDA_PRIV_KEY_FILE);

            // Carrega a Chave Pública do Datacenter (para comunicação TCP)
            datacenterPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDatacenter.DATACENTER_PUB_KEY_FILE);

            System.out.println("Borda: Chaves RSA geradas/carregadas. Aguardando Dispositivos na porta UDP " + UDP_PORT + "...");
            
            // Inicia o listener UDP
            startUDPListener();
            
        } catch (Exception e) {
            System.err.println("Erro fatal na Borda: " + e.getMessage());
        }
    }

    private static void startUDPListener() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(UDP_PORT)) {
            byte[] buffer = new byte[1024 * 10]; // Buffer grande para receber o objeto serializado
            
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                
                // Processa a mensagem em uma nova thread
                new Thread(() -> processUDPPacket(packet)).start();
            }
        }
    }
    
    private static void processUDPPacket(DatagramPacket packet) {
        try {
            // Extrai a mensagem criptografada
            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());
            
            // Deserializar Mensagem Criptografada
            MensagemCriptografada msg = (MensagemCriptografada) CriptografiaHibrida.deserialize(data);
            
            // Descriptografar a chave AES com a chave PRIVADA da Borda
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            
            // Descriptografar os Dados Coletados com a chave AES
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            
            // Deserializar para obter os Dados Coletados
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // Simulação de Autenticação e Verificação de Dispositivo Inválido
            if (dados.getDispositivoId().startsWith("DI_")) {
                System.err.println("⚠️ BORDA: PACOTE REJEITADO! Dispositivo Inválido (" + dados.getDispositivoId() + ") tentou se conectar. Descartando pacote.");
                return;
            }
            
            // Simulação de Análise Rápida (Alerta de Borda)
            if (dados.getTemperatura() > 39.0) {
                 System.out.println("🚨 BORDA ALERTA RÁPIDO: Dispositivo " + dados.getDispositivoId() + " detectou TEMP EXTREMA (Ação Imediata).");
            }

            // Envio do Dado ao Datacenter (TCP Criptografado)
            forwardToDatacenter(dados);
            
        } catch (Exception e) {
            System.err.println("Borda: Erro de descriptografia/processamento do pacote UDP. Descartado. " + e.getMessage());
        }
    }

    // Encaminha os dados, aplicando novamente a Criptografia Híbrida para o Datacenter
    private static void forwardToDatacenter(DadosColetados dados) {
        try (Socket socket = new Socket(DATACENTER_IP, DATACENTER_TCP_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {
            
            // Criptografar para o Datacenter
            byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
            SecretKey aesKey = CriptografiaHibrida.generateAESKey();
            byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
            byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, datacenterPublicKey);
            
            MensagemCriptografada msgDatacenter = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);

            // Enviar via TCP
            oos.writeObject(msgDatacenter);
            oos.flush();
            System.out.println("Borda: Dados de " + dados.getDispositivoId() + " encaminhados ao Datacenter (TCP/Híbrido).");
            
        } catch (ConnectException e) {
             System.err.println("Borda: ERRO DE CONEXÃO. Datacenter não está rodando na porta " + DATACENTER_TCP_PORT + ".");
        } catch (Exception e) {
            System.err.println("Borda: Erro ao encaminhar dados via TCP: " + e.getMessage());
        }
    }
}