package PraticaOffiline2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;

public class ServidorBorda {
    public static final String SERVER_IP = "127.0.0.1";
    public static final int UDP_PORT = 5555; 
    
    private static final String DATACENTER_IP = "127.0.0.1";
    public static final int DATACENTER_TCP_PORT = 8888; 
    
    public static final String BORDA_PUB_KEY_FILE = "borda.pub";
    
    private static PrivateKey rsaPrivateKey;
    private static PublicKey datacenterPublicKey; 
    
    // Simulação do Cache (Armazenamento temporário dos últimos 50 pacotes)
    private static final int CACHE_SIZE = 50;
    private static final List<DadosColetados> cache = Collections.synchronizedList(new LinkedList<>());

    public static void main(String[] args) {
        System.out.println("--- BORDA INICIADA ---");
        try {
            // 1. Geração e Salvamento das Chaves RSA da Borda
            KeyPair keyPair = CriptografiaHibrida.generateRSAKeyPair();
            rsaPrivateKey = keyPair.getPrivate();
            PublicKey rsaPublicKey = keyPair.getPublic();
            CriptografiaHibrida.savePublicKeyToFile(rsaPublicKey, BORDA_PUB_KEY_FILE);

            // 2. Carrega a Chave Pública do Datacenter
            datacenterPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDatacenter.DATACENTER_PUB_KEY_FILE);

            System.out.println("Borda: Chaves RSA geradas/carregadas. Aguardando Dispositivos na porta UDP " + UDP_PORT + "...");
            
            // 3. Inicia o listener UDP
            startUDPListener();
            
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
    
    private static void processUDPPacket(DatagramPacket packet) {
        try {
            // 1. Descriptografia Híbrida (UDP)
            byte[] data = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());
            MensagemCriptografada msg = (MensagemCriptografada) CriptografiaHibrida.deserialize(data);
            SecretKey aesKey = CriptografiaHibrida.decryptAESKeyWithRSA(
                msg.getChaveSimetricaCriptografada(), rsaPrivateKey);
            byte[] decryptedData = CriptografiaHibrida.decryptAES(
                msg.getDadosCriptografados(), aesKey);
            DadosColetados dados = (DadosColetados) CriptografiaHibrida.deserialize(decryptedData);
            
            // 2. Autenticação e Verificação de Dispositivo Inválido (Simulado)
            if (dados.getDispositivoId().startsWith("DI_")) {
                System.err.println("⚠️ BORDA: PACOTE REJEITADO! Dispositivo Inválido (" + dados.getDispositivoId() + "). Descartando pacote.");
                return;
            }
            
            // 3. Análise Rápida (Alerta de Borda)
            if (dados.getTemperatura() > 39.0) {
                 System.out.println("🚨 BORDA ALERTA RÁPIDO: Dispositivo " + dados.getDispositivoId() + " detectou TEMP EXTREMA.");
            }

            // 4. Implementação do Cache
            addToCache(dados);

            // 5. Envio do Dado ao Datacenter (TCP Criptografado)
            forwardToDatacenter(dados);
            
        } catch (Exception e) {
            System.err.println("Borda: Erro de descriptografia/processamento do pacote UDP. Descartado. " + e.getMessage());
        }
    }

    private static void addToCache(DadosColetados dados) {
        // Adiciona e mantém o cache no tamanho limite
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
            System.out.println("Borda: Dados de " + dados.getDispositivoId() + " encaminhados ao Datacenter (TCP/Híbrido).");
            
        } catch (ConnectException e) {
             System.err.println("Borda: ERRO DE CONEXÃO. Datacenter não está rodando na porta " + DATACENTER_TCP_PORT + ".");
        } catch (Exception e) {
            System.err.println("Borda: Erro ao encaminhar dados via TCP: " + e.getMessage());
        }
    }
}