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
    private final String token; // Token de autenticação
    private static PublicKey bordaPublicKey;
    private final Random random = new Random();

    public Dispositivo(String id, String token) { 
        this.dispositivoId = id;
        this.token = token;
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

        // Simulação de Dispositivos (D1, D2, D3, D4 + Dispositivo Inválido)
        Dispositivo d1 = new Dispositivo("D1_Correto", "keyD1");
        Dispositivo d2 = new Dispositivo("D2_Correto", "keyD2");
        Dispositivo d3 = new Dispositivo("D3_Correto", "keyD3");
        Dispositivo d4 = new Dispositivo("D4_Correto", "keyD4"); 
        // Credenciais Inválidas
        Dispositivo d_invalido = new Dispositivo("DI_Invalido", "token_errado"); 

        new Thread(() -> d1.iniciarColeta()).start();
        new Thread(() -> d2.iniciarColeta()).start();
        new Thread(() -> d3.iniciarColeta()).start();
        new Thread(() -> d4.iniciarColeta()).start();
        new Thread(() -> d_invalido.iniciarColeta()).start();
        
        System.out.println("\nSIMULAÇÃO: Dispositivos tentarão autenticar e enviarão dados por ~5 minutos.");
    }

    private void iniciarColeta() {
        // 1. Descoberta e 2. Autenticação (Redirecionamento para Borda)
        LocalizacaoResponse response = localizarESeAutenticar("BORDA");

        if (response == null || !response.isAutenticado()) {
            System.err.println("Dispositivo " + dispositivoId + ": Autenticação falhou ou Localização indisponível. Encerrando.");
            return;
        }

        String bordaIp = response.getEnderecoServico();
        int bordaPort = response.getPortaServico();

        System.out.println("Dispositivo " + dispositivoId + " autenticado. Redirecionado para Borda em " + bordaIp + ":" + bordaPort + ".");
        
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName(bordaIp);

            for (int i = 1; i <= REPETICOES_TOTAIS; i++) {
                
                // Lógica de coleta, criptografia híbrida e envio UDP
                DadosColetados dados = new DadosColetados(dispositivoId);
                byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
                
                SecretKey aesKey = CriptografiaHibrida.generateAESKey();
                byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
                
                byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, bordaPublicKey);
                
                MensagemCriptografada mensagem = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);
                byte[] mensagemBytes = CriptografiaHibrida.serialize(mensagem);

                DatagramPacket packet = new DatagramPacket(mensagemBytes, mensagemBytes.length, address, bordaPort);
                socket.send(packet);
                
                System.out.println("Dispositivo " + dispositivoId + ": Envio " + i + "/" + REPETICOES_TOTAIS + " via UDP (Híbrido).");
                
                // Esperar entre 2 e 3 segundos
                long sleepTime = 2000 + random.nextInt(1000); 
                TimeUnit.MILLISECONDS.sleep(sleepTime);
            }
            
            System.out.println("Dispositivo " + dispositivoId + ": FINALIZOU a coleta de dados após 5 minutos.");
            
        } catch (Exception e) {
            System.err.println("Dispositivo " + dispositivoId + ": Erro durante o ciclo de envio. " + e.getMessage());
        }
    }
    
    private LocalizacaoResponse localizarESeAutenticar(String tipoServico) {
        try (Socket socket = new Socket(ServidorDeLocalizacaoEAutenticacao.SERVER_IP, ServidorDeLocalizacaoEAutenticacao.LOCALIZACAO_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            // Envia ID, Token e Tipo de Serviço
            oos.writeObject(dispositivoId);
            oos.writeObject(token);
            oos.writeObject(tipoServico);
            oos.flush();

            return (LocalizacaoResponse) ois.readObject();

        } catch (Exception e) {
            System.err.println("Dispositivo " + dispositivoId + ": Falha ao se comunicar com o Servidor de Localização. " + e.getMessage());
            return null;
        }
    }
}