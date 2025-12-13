package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class Dispositivo {
    public static final String BORDA_PUB_KEY_FILE = "borda.pub"; 
    private static final int TEMPO_TOTAL_SEGUNDOS = 300; // 5 minutos
    private static final int REPETICOES_TOTAIS = (int) Math.ceil(TEMPO_TOTAL_SEGUNDOS / 2.5); 

    private final String dispositivoId;
    private final String token; 
    private final boolean simulaAnomalia; // Flag para simular dados anômalos
    
    // Chaves públicas necessárias
    private static PublicKey bordaPublicKey;
    private static PublicKey authPublicKey; 
    private static PublicKey locPublicKey;  
    
    private final Random random = new Random();

    public Dispositivo(String id, String token) { 
        this(id, token, false);
    }
    
    public Dispositivo(String id, String token, boolean simulaAnomalia) {
        this.dispositivoId = id;
        this.token = token;
        this.simulaAnomalia = simulaAnomalia;
    }

    public static void main(String[] args) throws Exception {
        
        System.out.println("==============================================");
        System.out.println("     DISPOSITIVOS IoT - Sistema de Coleta     ");
        System.out.println("==============================================\n");
        
        // 1. CARREGAMENTO DAS CHAVES PÚBLICAS
        try {
            System.out.println("🔑 Carregando chaves públicas dos servidores...");
            bordaPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(BORDA_PUB_KEY_FILE);
            System.out.println("   ✅ Chave da Borda carregada: " + BORDA_PUB_KEY_FILE);
            
            authPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
            System.out.println("   ✅ Chave de Autenticação carregada: " + ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
            
            locPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeLocalizacao.LOC_PUB_KEY_FILE); 
            System.out.println("   ✅ Chave de Localização carregada: " + ServidorDeLocalizacao.LOC_PUB_KEY_FILE);
            
            System.out.println("\n✅ Todas as chaves públicas carregadas com sucesso!\n");
        } catch (Exception e) {
            System.err.println("❌ ERRO CRÍTICO: Não foi possível carregar todas as chaves públicas.");
            System.err.println("   Certifique-se que os Servidores foram inicializados primeiro.");
            System.err.println("   Detalhes: " + e.getMessage());
            return;
        }

        System.out.println("==============================================");
        System.out.println("     INICIANDO SIMULAÇÃO DE DISPOSITIVOS      ");
        System.out.println("==============================================\n");
        
        // 2. CRIAÇÃO DOS DISPOSITIVOS
        System.out.println("📱 Criando dispositivos para simulação:");
        
        Dispositivo d1 = new Dispositivo("D1_Correto", "keyD1");
        System.out.println("   → D1_Correto (Normal)");
        
        Dispositivo d2 = new Dispositivo("D2_Correto", "keyD2");
        System.out.println("   → D2_Correto (Normal)");
        
        Dispositivo d3 = new Dispositivo("D3_Correto", "keyD3");
        System.out.println("   → D3_Correto (Normal)");
        
        Dispositivo d4 = new Dispositivo("D4_Correto", "keyD4");
        System.out.println("   → D4_Correto (Normal)");
        
        Dispositivo d5_anomalo = new Dispositivo("D5_Anomalo", "keyD5", true);
        System.out.println("   → D5_Anomalo (ANOMALIA - Temperatura Extrema)");
        
        Dispositivo di_invalido = new Dispositivo("DI_Invalido", "token_errado");
        System.out.println("   → DI_Invalido (Credenciais Inválidas - será rejeitado)\n");

        System.out.println("==============================================");
        System.out.println("SIMULAÇÃO: Os dispositivos irão:");
        System.out.println("1. Autenticar no Servidor de Autenticação");
        System.out.println("2. Localizar a Borda via Servidor de Localização");
        System.out.println("3. Enviar dados a cada ~2.5s por 5 minutos");
        System.out.println("4. Dados criptografados com AES + RSA (Híbrido)");
        System.out.println("==============================================\n");

        // 3. INICIALIZAÇÃO DAS THREADS
        new Thread(() -> d1.iniciarColeta()).start();
        TimeUnit.MILLISECONDS.sleep(200); // Pequeno delay entre inicializações
        
        new Thread(() -> d2.iniciarColeta()).start();
        TimeUnit.MILLISECONDS.sleep(200);
        
        new Thread(() -> d3.iniciarColeta()).start();
        TimeUnit.MILLISECONDS.sleep(200);
        
        new Thread(() -> d4.iniciarColeta()).start();
        TimeUnit.MILLISECONDS.sleep(200);
        
        new Thread(() -> d5_anomalo.iniciarColeta()).start();
        TimeUnit.MILLISECONDS.sleep(200);
        
        new Thread(() -> di_invalido.iniciarColeta()).start();
        
        System.out.println("🚀 Todos os dispositivos foram iniciados!\n");
    }

    private void iniciarColeta() {
        System.out.println("─────────────────────────────────────────────");
        System.out.println("🔄 Dispositivo " + dispositivoId + " iniciando processo...");
        System.out.println("─────────────────────────────────────────────");
        
        // FASE 1: AUTENTICAÇÃO (TCP Híbrido)
        System.out.println("📍 FASE 1: Autenticação");
        AutenticacaoResponse authResponse = solicitarAutenticacao(dispositivoId, token, authPublicKey);

        if (authResponse == null || !authResponse.isAutenticado()) {
            System.err.println("❌ " + dispositivoId + ": Autenticação FALHOU. Encerrando.");
            if (authResponse != null) {
                System.err.println("   Motivo: " + authResponse.getMensagem());
            }
            System.err.println("─────────────────────────────────────────────\n");
            return;
        }
        System.out.println("✅ " + dispositivoId + ": " + authResponse.getMensagem());

        // FASE 2: LOCALIZAÇÃO (TCP Híbrido)
        System.out.println("📍 FASE 2: Localização do Servidor de Borda");
        LocalizacaoResponse locResponse = solicitarLocalizacao(dispositivoId, "BORDA", locPublicKey);

        if (locResponse == null || !locResponse.isAutenticado()) {
            System.err.println("❌ " + dispositivoId + ": Localização FALHOU. Encerrando.");
            System.err.println("─────────────────────────────────────────────\n");
            return;
        }

        String bordaIp = locResponse.getEnderecoServico();
        int bordaPort = locResponse.getPortaServico();

        System.out.println("✅ " + dispositivoId + ": Borda localizada em " + bordaIp + ":" + bordaPort);
        System.out.println("─────────────────────────────────────────────");
        
        // FASE 3: CICLO DE COLETA E ENVIO (UDP Híbrido)
        System.out.println("📍 FASE 3: Iniciando coleta e envio de dados");
        System.out.println("   → Envios programados: " + REPETICOES_TOTAIS);
        System.out.println("   → Intervalo: ~2.5s entre envios");
        System.out.println("   → Duração total: ~5 minutos");
        if (simulaAnomalia) {
            System.out.println("   ⚠️  MODO ANOMALIA: Temperatura EXTREMA será gerada!");
        }
        System.out.println("─────────────────────────────────────────────\n");
        
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName(bordaIp);
            int enviosRealizados = 0;
            int errosEnvio = 0;

            for (int i = 1; i <= REPETICOES_TOTAIS; i++) {
                try {
                    // Gera dados (normais ou anômalos)
                    DadosColetados dados = new DadosColetados(dispositivoId, simulaAnomalia);
                    byte[] dadosSerializados = CriptografiaHibrida.serialize(dados);
                    
                    // Criptografia Híbrida (AES para dados + RSA para chave AES)
                    SecretKey aesKey = CriptografiaHibrida.generateAESKey();
                    byte[] dadosCriptografados = CriptografiaHibrida.encryptAES(dadosSerializados, aesKey);
                    byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, bordaPublicKey);
                    
                    MensagemCriptografada mensagem = new MensagemCriptografada(chaveAESCriptografada, dadosCriptografados);
                    byte[] mensagemBytes = CriptografiaHibrida.serialize(mensagem);

                    // Envio UDP
                    DatagramPacket packet = new DatagramPacket(mensagemBytes, mensagemBytes.length, address, bordaPort);
                    socket.send(packet);
                    enviosRealizados++;
                    
                    // Log detalhado a cada 10 envios ou se for anômalo
                    if (i % 10 == 0 || simulaAnomalia) {
                        System.out.printf("📤 %s [%d/%d]: Temp=%.1f°C | CO2=%.0fppm | Enviado %db\n",
                            dispositivoId, i, REPETICOES_TOTAIS, 
                            dados.getTemperatura(), dados.getCo2(), mensagemBytes.length);
                    } else if (i == 1) {
                        System.out.printf("📤 %s [%d/%d]: Primeiro envio OK (Temp=%.1f°C)\n",
                            dispositivoId, i, REPETICOES_TOTAIS, dados.getTemperatura());
                    }
                    
                    // Intervalo variável entre 2-3 segundos
                    long sleepTime = 2000 + random.nextInt(1000); 
                    TimeUnit.MILLISECONDS.sleep(sleepTime);
                    
                } catch (Exception e) {
                    errosEnvio++;
                    System.err.println("⚠️  " + dispositivoId + " [" + i + "]: Erro no envio - " + e.getMessage());
                    
                    // Se muitos erros consecutivos, aborta
                    if (errosEnvio > 5) {
                        System.err.println("❌ " + dispositivoId + ": Muitos erros. Abortando coleta.");
                        break;
                    }
                }
            }
            
            System.out.println("\n─────────────────────────────────────────────");
            System.out.println("✅ " + dispositivoId + ": COLETA FINALIZADA");
            System.out.println("   → Envios bem-sucedidos: " + enviosRealizados + "/" + REPETICOES_TOTAIS);
            if (errosEnvio > 0) {
                System.out.println("   → Erros: " + errosEnvio);
            }
            System.out.println("─────────────────────────────────────────────\n");
            
        } catch (Exception e) {
            System.err.println("❌ " + dispositivoId + ": Erro crítico no ciclo de coleta.");
            System.err.println("   Detalhes: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // ===== MÉTODOS DE COMUNICAÇÃO HÍBRIDA (TCP) =====

    private AutenticacaoResponse solicitarAutenticacao(String id, String token, PublicKey authPublicKey) {
        try (Socket socket = new Socket(ServidorDeAutenticacao.SERVER_IP, ServidorDeAutenticacao.AUTH_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("   🔐 Conectando ao Servidor de Autenticação...");
            
            MensagemLogin login = new MensagemLogin(id, token, null); 
            SecretKey aesKey = enviarRequisicaoHibrida(oos, login, authPublicKey);

            System.out.println("   📤 Credenciais enviadas (criptografadas)");
            System.out.println("   📥 Aguardando resposta...");
            
            AutenticacaoResponse response = (AutenticacaoResponse) receberRespostaHibrida(ois, aesKey);
            
            return response;

        } catch (ConnectException e) {
            System.err.println("   ❌ Falha de conexão: Servidor de Autenticação offline");
            return new AutenticacaoResponse(false, "Servidor Indisponível");
        } catch (Exception e) {
            System.err.println("   ❌ Erro na autenticação: " + e.getMessage());
            return new AutenticacaoResponse(false, "Erro de Comunicação");
        }
    }

    private LocalizacaoResponse solicitarLocalizacao(String id, String tipoServico, PublicKey locPublicKey) {
        try (Socket socket = new Socket(ServidorDeLocalizacao.SERVER_IP, ServidorDeLocalizacao.LOC_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("   🗺️  Conectando ao Servidor de Localização...");
            
            MensagemLogin requisicao = new MensagemLogin(id, null, tipoServico);
            SecretKey aesKey = enviarRequisicaoHibrida(oos, requisicao, locPublicKey);

            System.out.println("   📤 Requisição de localização enviada: " + tipoServico);
            System.out.println("   📥 Aguardando coordenadas...");
            
            LocalizacaoResponse response = (LocalizacaoResponse) receberRespostaHibrida(ois, aesKey);
            
            return response;

        } catch (ConnectException e) {
            System.err.println("   ❌ Falha de conexão: Servidor de Localização offline");
            return new LocalizacaoResponse(false, null, 0);
        } catch (Exception e) {
            System.err.println("   ❌ Erro na localização: " + e.getMessage());
            return new LocalizacaoResponse(false, null, 0);
        }
    }
    
    // Método reutilizável para enviar requisição (AES + Chave RSA)
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

    // Método reutilizável para receber e descriptografar resposta (apenas AES)
    private Object receberRespostaHibrida(ObjectInputStream ois, SecretKey aesKey) throws Exception {
        MensagemCriptografada msgResposta = (MensagemCriptografada) ois.readObject();
        
        byte[] responseCriptografada = msgResposta.getDadosCriptografados();
        byte[] responseDecrypted = CriptografiaHibrida.decryptAES(responseCriptografada, aesKey);
        
        return CriptografiaHibrida.deserialize(responseDecrypted);
    }
}