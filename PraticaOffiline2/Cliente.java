package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class Cliente {
    // Credenciais do Cliente Gestor Urbano
    private static final String CLIENTE_ID = "Gestor_Urbano";
    private static final String CLIENTE_TOKEN = "keyGU"; 
    
    private static String DATACENTER_IP = null;
    private static int DATACENTER_CONSULTA_PORT = 0; 
    
    // Chaves públicas necessárias
    private static PublicKey authPublicKey; 
    private static PublicKey locPublicKey;  
    
    public static void main(String[] args) throws Exception {
        System.out.println("--- CLIENTE INICIADO ---");
        
        // 1. CARREGAMENTO DAS CHAVES PÚBLICAS
        try {
            authPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
            locPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeLocalizacao.LOC_PUB_KEY_FILE); 
            System.out.println("Cliente: Chaves públicas carregadas com sucesso (Auth, Loc).");
        } catch (Exception e) {
            System.err.println("ERRO: Não foi possível carregar todas as chaves públicas. " + e.getMessage());
            return;
        }

        // FASE 1: AUTENTICAÇÃO (TCP Híbrido)
        AutenticacaoResponse authResponse = solicitarAutenticacao(CLIENTE_ID, CLIENTE_TOKEN, authPublicKey);

        if (authResponse == null || !authResponse.isAutenticado()) {
            System.err.println("Cliente " + CLIENTE_ID + ": Autenticação falhou. Encerrando.");
            return;
        }
        System.out.println("Cliente " + CLIENTE_ID + ": " + authResponse.getMensagem());
        
        // FASE 2: LOCALIZAÇÃO (TCP Híbrido)
        LocalizacaoResponse locResponse = solicitarLocalizacao(CLIENTE_ID, "DATACENTER", locPublicKey);

        if (locResponse == null || !locResponse.isAutenticado()) {
            System.err.println("Cliente " + CLIENTE_ID + ": Localização indisponível. Encerrando.");
            return;
        }
        
        DATACENTER_IP = locResponse.getEnderecoServico();
        DATACENTER_CONSULTA_PORT = locResponse.getPortaServico();
        
        System.out.println("Cliente Gestor_Urbano localizado. Servidor Datacenter em " + DATACENTER_IP + ":" + DATACENTER_CONSULTA_PORT + ".");
        
        int tempoEsperaSegundos = 60; 
        System.out.println("Aguardando coleta de dados (Simulação por " + tempoEsperaSegundos + "s)...");
        try {
            TimeUnit.SECONDS.sleep(tempoEsperaSegundos);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        consultarEProcessarDados();
    }
    
    // --- MÉTODOS DE COMUNICAÇÃO HÍBRIDA (NOVA ARQUITETURA) ---

    private static AutenticacaoResponse solicitarAutenticacao(String id, String token, PublicKey authPublicKey) {
        try (Socket socket = new Socket(ServidorDeAutenticacao.SERVER_IP, ServidorDeAutenticacao.AUTH_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            MensagemLogin login = new MensagemLogin(id, token, null); 
            SecretKey aesKey = enviarRequisicaoHibrida(oos, login, authPublicKey);

            return (AutenticacaoResponse) receberRespostaHibrida(ois, aesKey);

        } catch (ConnectException e) {
            System.err.println("Cliente " + id + ": Falha ao conectar ao Servidor de Autenticação.");
            return null;
        } catch (Exception e) {
            System.err.println("Cliente " + id + ": Erro no processo de Autenticação. " + e.getMessage());
            return null;
        }
    }

    private static LocalizacaoResponse solicitarLocalizacao(String id, String tipoServico, PublicKey locPublicKey) {
         try (Socket socket = new Socket(ServidorDeLocalizacao.SERVER_IP, ServidorDeLocalizacao.LOC_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            MensagemLogin requisicao = new MensagemLogin(id, null, tipoServico);
            SecretKey aesKey = enviarRequisicaoHibrida(oos, requisicao, locPublicKey);

            return (LocalizacaoResponse) receberRespostaHibrida(ois, aesKey);

        } catch (ConnectException e) {
            System.err.println("Cliente " + id + ": Falha ao conectar ao Servidor de Localização.");
            return null;
        } catch (Exception e) {
            System.err.println("Cliente " + id + ": Erro no processo de Localização. " + e.getMessage());
            return null;
        }
    }
    
    // Métodos utilitários de comunicação (copiados de Dispositivo, renomeados para static)
    private static SecretKey enviarRequisicaoHibrida(ObjectOutputStream oos, Serializable payload, PublicKey serverPublicKey) throws Exception {
        byte[] payloadSerializado = CriptografiaHibrida.serialize(payload);
        
        SecretKey aesKey = CriptografiaHibrida.generateAESKey();
        byte[] payloadCriptografado = CriptografiaHibrida.encryptAES(payloadSerializado, aesKey);
        
        byte[] chaveAESCriptografada = CriptografiaHibrida.encryptAESKeyWithRSA(aesKey, serverPublicKey);
        
        MensagemCriptografada msgRequisicao = new MensagemCriptografada(chaveAESCriptografada, payloadCriptografado);
        oos.writeObject(msgRequisicao);
        oos.flush();
        
        return aesKey;
    }

    private static Object receberRespostaHibrida(ObjectInputStream ois, SecretKey aesKey) throws Exception {
        MensagemCriptografada msgResposta = (MensagemCriptografada) ois.readObject();
        
        byte[] responseCriptografada = msgResposta.getDadosCriptografados();
        byte[] responseDecrypted = CriptografiaHibrida.decryptAES(responseCriptografada, aesKey);
        
        return CriptografiaHibrida.deserialize(responseDecrypted);
    }
    
    // --- LÓGICA DE CONSULTA E ANÁLISE ---

    private static void consultarEProcessarDados() {
        // ... (Corpo do método permanece o mesmo do código original)
        System.out.println("\n--- INICIANDO CONSULTA DE DADOS ---");
        try (Socket socket = new Socket(DATACENTER_IP, DATACENTER_CONSULTA_PORT);
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            @SuppressWarnings("unchecked")
            List<DadosColetados> dados = (List<DadosColetados>) ois.readObject();
            
            if (dados.isEmpty()) {
                System.out.println("Não há dados coletados no Datacenter para análise.");
                return;
            }

            System.out.println("Recebidos " + dados.size() + " registros do Datacenter.");
            realizarAnalise(dados);
            
        } catch (ConnectException e) {
            System.err.println("ERRO DE CONEXÃO: Certifique-se de que o ServidorDatacenter está rodando na porta " + DATACENTER_CONSULTA_PORT + ".");
        } catch (Exception e) {
            System.err.println("Erro ao processar dados: " + e.getMessage());
        }
    }
    
    private static void realizarAnalise(List<DadosColetados> dados) {
        // ... (Corpo do método permanece o mesmo do código original)
        System.out.println("\n--- ANÁLISE GESTOR URBANO ---");
        
        // RELATÓRIO: Médias Gerais 
        System.out.println("\n[1. RELATÓRIO DE MÉDIAS]");
        double mediaTemp = dados.stream().mapToDouble(d -> d.getTemperatura()).average().orElse(0.0);
        double mediaCO2 = dados.stream().mapToDouble(d -> d.getCo2()).average().orElse(0.0);
        double mediaRuido = dados.stream().mapToDouble(d -> d.getRuido()).average().orElse(0.0);
        double mediaUmidade = dados.stream().mapToDouble(d -> d.getUmidade()).average().orElse(0.0);
        double mediaPM25 = dados.stream().mapToDouble(d -> d.getPm25()).average().orElse(0.0);
        
        System.out.printf("Média de Temperatura: %.2f °C\n", mediaTemp);
        System.out.printf("Média de CO2: %.2f ppm\n", mediaCO2);
        System.out.printf("Média de Ruído: %.2f dB\n", mediaRuido);
        System.out.printf("Média de Umidade: %.2f %%\n", mediaUmidade);
        System.out.printf("Média de PM2.5: %.2f µg/m³\n", mediaPM25);
        
        
        // ALERTA: Detecção de Temperatura Crítica
        long alertasTemp = dados.stream()
            .filter(d -> d.getTemperatura() > 35.0)
            .count();
            
        if (alertasTemp > 0) {
            System.out.println("\n[2. ALERTA DE TEMPERATURA CRÍTICA]");
            System.out.println("🚨 " + alertasTemp + " medições acima de 35°C (Requer atenção imediata).");
            dados.stream()
                .filter(d -> d.getTemperatura() > 35.0)
                .limit(3) 
                .forEach(d -> System.out.printf("   -> ID %s: %.1f °C\n", d.getDispositivoId(), d.getTemperatura()));
        } else {
             System.out.println("\n[2. ALERTA DE TEMPERATURA CRÍTICA] Status: OK. Nenhuma medição crítica.");
        }
        
        // ALERTA: Poluição de Partículas (PM2.5 e PM10)
        long alertasPM = dados.stream()
            .filter(d -> d.getPm25() > 25.0 || d.getPm10() > 50.0)
            .count();
            
        if (alertasPM > (dados.size() * 0.1)) { 
            System.out.println("\n[3. ALERTA DE POLUIÇÃO POR PARTÍCULAS]");
            System.out.println("⚠️ " + alertasPM + " medições com PM2.5 ou PM10 elevado (Sugere restrição de atividades ao ar livre).");
        } else {
             System.out.println("\n[3. ALERTA DE POLUIÇÃO POR PARTÍCULAS] Status: OK. Nível de partículas sob controle.");
        }
        
        // ALERTA: Risco de Poluição Química (CO, NO2, SO2)
        long alertasQuimicos = dados.stream()
            .filter(d -> d.getCo() > 4.5 || d.getNo2() > 80.0 || d.getSo2() > 40.0) 
            .count();
            
        if (alertasQuimicos > 0) {
             System.out.println("\n[4. ALERTA DE POLUIÇÃO QUÍMICA]");
             System.out.println("🔥 " + alertasQuimicos + " medições com picos de CO, NO2 ou SO2. (Investigar fontes industriais ou tráfego intenso).");
        } else {
             System.out.println("\n[4. ALERTA DE POLUIÇÃO QUÍMICA] Status: OK. Poluentes gasosos controlados.");
        }
        
        // PREVISÃO/ALERTA: Risco de Seca e Desidratação (Baixa Umidade e Alto UV)
        long alertasUmidade = dados.stream()
            .filter(d -> d.getUmidade() < 40.0 && d.getRadiacaoUV() > 8.0) 
            .count();
        
        if (alertasUmidade > 0) {
            System.out.println("\n[5. PREVISÃO: RISCO DE SAÚDE AMBIENTAL]");
            System.out.println("💧 Atenção! " + alertasUmidade + " ocorrências de baixa umidade e UV alto. (Recomendar hidratação e proteção solar).");
        } else {
            System.out.println("\n[5. PREVISÃO: RISCO DE SAÚDE AMBIENTAL] Status: OK. Condições climáticas estáveis.");
        }
    }
}