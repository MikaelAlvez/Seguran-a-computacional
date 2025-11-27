package PraticaOffiline2;

import java.net.*;
import java.security.PublicKey;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class Dispositivo {
    private static final String BORDA_IP = "127.0.0.1";
    public static final int UDP_PORT = 5555; 
    public static final String BORDA_PUB_KEY_FILE = "borda.pub"; 

    // Parâmetros de tempo da simulação
    private static final int TEMPO_TOTAL_SEGUNDOS = 300; // 5 minutos
    // Intervalo de envio será entre 2 e 3 segundos (média de 2.5s)
    private static final int REPETICOES_TOTAIS = (int) Math.ceil(TEMPO_TOTAL_SEGUNDOS / 3); 

    private final String dispositivoId;
    private static PublicKey bordaPublicKey;
    private final Random random = new Random();

    public Dispositivo(String id) {
        this.dispositivoId = id;
    }

    public static void main(String[] args) throws Exception {
        // Carrega a chave pública da Borda
        try {
            bordaPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(BORDA_PUB_KEY_FILE);
            System.out.println("Dispositivo: Chave pública da Borda carregada com sucesso.");
        } catch (Exception e) {
            System.err.println("ERRO: Não foi possível carregar a chave pública da Borda. Certifique-se que '" + BORDA_PUB_KEY_FILE + "' existe.");
            return;
        }

        // Simulação de Dispositivos (D1, D2, D3, D4, DI_Invalido)
        Dispositivo d1 = new Dispositivo("D1_Correto");
        Dispositivo d2 = new Dispositivo("D2_Correto");
        Dispositivo d3 = new Dispositivo("D3_Correto");
        // Dispositivo Inválido (Para o teste de autenticação)
        Dispositivo d_invalido = new Dispositivo("DI_Invalido"); 

        new Thread(() -> d1.iniciarColeta()).start();
        new Thread(() -> d2.iniciarColeta()).start();
        new Thread(() -> d3.iniciarColeta()).start();
        new Thread(() -> d_invalido.iniciarColeta()).start();
        
        System.out.println("\nSIMULAÇÃO: Quatro dispositivos iniciarão o envio de dados e finalizarão após aproximadamente 5 minutos (" + REPETICOES_TOTAIS + " envios).");
    }

    private void iniciarColeta() {
        System.out.println("Dispositivo " + dispositivoId + " iniciado e coletando dados...");
        
        // O loop agora usa um contador para limitar o número de envios
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName(BORDA_IP);

            for (int i = 1; i <= REPETICOES_TOTAIS; i++) {
                
                // Coletar Dados
                DadosColetados dados = new DadosColetados(dispositivoId);
                byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
                
                // Gerar Chave AES e Criptografar Dados
                SecretKey aesKey = CriptografiaHibrida.generateAESKey();
                byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
                
                // Criptografar Chave AES com RSA Pública da Borda
                byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, bordaPublicKey);
                
                // Montar a Mensagem Híbrida
                MensagemCriptografada mensagem = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);
                byte[] mensagemBytes = CriptografiaHibrida.serialize(mensagem);

                // Enviar via UDP
                DatagramPacket packet = new DatagramPacket(mensagemBytes, mensagemBytes.length, address, UDP_PORT);
                socket.send(packet);
                
                // Log simplificado
                System.out.println("Dispositivo " + dispositivoId + ": Envio " + i + "/" + REPETICOES_TOTAIS + " via UDP (Híbrido).");
                
                // Esperar entre 2 e 3 segundos
                // Gera um tempo de espera entre 2000ms e 3000ms
                long sleepTime = 2000 + random.nextInt(1000); 
                TimeUnit.MILLISECONDS.sleep(sleepTime);
            }
            
            System.out.println("Dispositivo " + dispositivoId + ": FINALIZOU a coleta de dados após 5 minutos.");
            
        } catch (Exception e) {
            System.err.println("Dispositivo " + dispositivoId + ": Erro durante o ciclo de envio. " + e.getMessage());
        }
    }
}