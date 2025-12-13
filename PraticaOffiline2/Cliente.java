package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
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
    private static PublicKey datacenterPublicKey;
    
    public static void main(String[] args) throws Exception {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║            CLIENTE GESTOR URBANO - SISTEMA DE CONSULTA     ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
        
        // 1. CARREGAMENTO DAS CHAVES PÚBLICAS
        try {
            System.out.println("🔑 Carregando chaves públicas...");
            authPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeAutenticacao.AUTH_PUB_KEY_FILE);
            locPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDeLocalizacao.LOC_PUB_KEY_FILE); 
            datacenterPublicKey = CriptografiaHibrida.loadPublicKeyFromFile(ServidorDatacenter.DATACENTER_PUB_KEY_FILE);
            System.out.println("✅ Todas as chaves públicas carregadas com sucesso!\n");
        } catch (Exception e) {
            System.err.println("❌ ERRO: Não foi possível carregar todas as chaves públicas.");
            System.err.println("   Detalhes: " + e.getMessage());
            return;
        }

        System.out.println("═".repeat(60));
        System.out.println("FASE 1: AUTENTICAÇÃO");
        System.out.println("═".repeat(60));
        
        // FASE 1: AUTENTICAÇÃO (TCP Híbrido)
        AutenticacaoResponse authResponse = solicitarAutenticacao(CLIENTE_ID, CLIENTE_TOKEN, authPublicKey);

        if (authResponse == null || !authResponse.isAutenticado()) {
            System.err.println("❌ " + CLIENTE_ID + ": Autenticação FALHOU. Encerrando.");
            if (authResponse != null) { 
                System.err.println("   Motivo: " + authResponse.getMensagem()); 
            }
            return;
        }
        System.out.println("✅ " + CLIENTE_ID + ": " + authResponse.getMensagem());
        
        System.out.println("\n" + "═".repeat(60));
        System.out.println("FASE 2: LOCALIZAÇÃO DO DATACENTER");
        System.out.println("═".repeat(60));
        
        // FASE 2: LOCALIZAÇÃO (TCP Híbrido)
        LocalizacaoResponse locResponse = solicitarLocalizacao(CLIENTE_ID, "DATACENTER", locPublicKey);

        if (locResponse == null || !locResponse.isAutenticado()) {
            System.err.println("❌ " + CLIENTE_ID + ": Localização indisponível. Encerrando.");
            return;
        }
        
        DATACENTER_IP = locResponse.getEnderecoServico();
        DATACENTER_CONSULTA_PORT = locResponse.getPortaServico();
        
        System.out.println("✅ Datacenter localizado em: " + DATACENTER_IP + ":" + DATACENTER_CONSULTA_PORT);
        
        // AGUARDA CONCLUSÃO DA SIMULAÇÃO (5 minutos)
        int tempoEsperaSegundos = 300; 
        System.out.println("\n" + "═".repeat(60));
        System.out.println("⏳ AGUARDANDO CONCLUSÃO DA SIMULAÇÃO");
        System.out.println("═".repeat(60));
        System.out.println("⏰ Tempo de espera: " + tempoEsperaSegundos + " segundos (5 minutos)");
        System.out.println("📊 Durante este período, os dispositivos estão coletando dados...\n");
        
        // Exibe contador regressivo a cada 30 segundos
        for (int i = tempoEsperaSegundos; i > 0; i -= 30) {
            if (i == tempoEsperaSegundos || i <= 60 || i % 60 == 0) {
                System.out.println("⏳ Aguardando... " + i + "s restantes");
            }
            TimeUnit.SECONDS.sleep(Math.min(30, i));
        }
        
        System.out.println("✅ Período de coleta finalizado!\n");
        
        // FASE 3: CONSULTAS E PROCESSAMENTO
        System.out.println("═".repeat(60));
        System.out.println("FASE 3: CONSULTAS AO DATACENTER");
        System.out.println("═".repeat(60) + "\n");
        
        // CONSULTA 1: Análise Geral dos Dados
        realizarConsulta1();
        
        TimeUnit.SECONDS.sleep(2);
        
        // CONSULTA 2: Análise de Segurança e Anomalias
        realizarConsulta2();
        
        // RELATÓRIOS FINAIS DE SEGURANÇA
        exibirRelatoriosSeguranca();
    }
    
    // ═════════════════════════════════════════════════════════════
    //                    CONSULTA 1: ANÁLISE GERAL
    // ═════════════════════════════════════════════════════════════
    
    private static void realizarConsulta1() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║          CONSULTA 1: ANÁLISE GERAL DOS DADOS               ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
        
        List<DadosColetados> dados = solicitarDadosHistoricos();
        
        if (dados == null || dados.isEmpty()) {
            System.out.println("❌ Não há dados disponíveis ou a comunicação falhou.\n");
            return;
        }
        
        System.out.println("✅ Recebidos " + dados.size() + " registros do Datacenter (Decriptografados)\n");
        
        // RELATÓRIO 1.1: Estatísticas por Dispositivo
        System.out.println("─".repeat(60));
        System.out.println("📊 RELATÓRIO 1.1: ESTATÍSTICAS POR DISPOSITIVO");
        System.out.println("─".repeat(60));
        
        Map<String, List<DadosColetados>> dadosPorDispositivo = dados.stream()
            .collect(Collectors.groupingBy(DadosColetados::getDispositivoId));
        
        System.out.printf("%-15s | %-8s | %-10s | %-10s | %-10s\n", 
            "Dispositivo", "Registros", "Temp Média", "CO2 Médio", "PM2.5 Médio");
        System.out.println("-".repeat(60));
        
        dadosPorDispositivo.forEach((id, lista) -> {
            double mediaTemp = lista.stream().mapToDouble(DadosColetados::getTemperatura).average().orElse(0.0);
            double mediaCO2 = lista.stream().mapToDouble(DadosColetados::getCo2).average().orElse(0.0);
            double mediaPM25 = lista.stream().mapToDouble(DadosColetados::getPm25).average().orElse(0.0);
            
            System.out.printf("%-15s | %-8d | %7.2f°C | %8.0f ppm | %8.2f µg/m³\n", 
                id, lista.size(), mediaTemp, mediaCO2, mediaPM25);
        });
        
        // RELATÓRIO 1.2: Médias Gerais
        System.out.println("\n" + "─".repeat(60));
        System.out.println("📈 RELATÓRIO 1.2: MÉDIAS GERAIS DA CIDADE");
        System.out.println("─".repeat(60));
        
        double mediaTemp = dados.stream().mapToDouble(DadosColetados::getTemperatura).average().orElse(0.0);
        double mediaCO2 = dados.stream().mapToDouble(DadosColetados::getCo2).average().orElse(0.0);
        double mediaCO = dados.stream().mapToDouble(DadosColetados::getCo).average().orElse(0.0);
        double mediaNO2 = dados.stream().mapToDouble(DadosColetados::getNo2).average().orElse(0.0);
        double mediaSO2 = dados.stream().mapToDouble(DadosColetados::getSo2).average().orElse(0.0);
        double mediaPM25 = dados.stream().mapToDouble(DadosColetados::getPm25).average().orElse(0.0);
        double mediaPM10 = dados.stream().mapToDouble(DadosColetados::getPm10).average().orElse(0.0);
        double mediaUmidade = dados.stream().mapToDouble(DadosColetados::getUmidade).average().orElse(0.0);
        double mediaRadiacao = dados.stream().mapToDouble(DadosColetados::getRadiacaoUV).average().orElse(0.0);
        double mediaRuido = dados.stream().mapToDouble(DadosColetados::getRuido).average().orElse(0.0);
        
        System.out.printf("🌡️  Temperatura Média: %.2f°C\n", mediaTemp);
        System.out.printf("💨 CO2 Médio: %.0f ppm\n", mediaCO2);
        System.out.printf("💨 CO Médio: %.2f ppm\n", mediaCO);
        System.out.printf("💨 NO2 Médio: %.2f ppb\n", mediaNO2);
        System.out.printf("💨 SO2 Médio: %.2f ppb\n", mediaSO2);
        System.out.printf("🌫️  PM2.5 Médio: %.2f µg/m³\n", mediaPM25);
        System.out.printf("🌫️  PM10 Médio: %.2f µg/m³\n", mediaPM10);
        System.out.printf("💧 Umidade Média: %.2f%%\n", mediaUmidade);
        System.out.printf("☀️  Radiação UV Média: %.2f\n", mediaRadiacao);
        System.out.printf("🔊 Ruído Médio: %.2f dB\n", mediaRuido);
        
        // RELATÓRIO 1.3: Qualidade do Ar
        System.out.println("\n" + "─".repeat(60));
        System.out.println("🌍 RELATÓRIO 1.3: ÍNDICE DE QUALIDADE DO AR");
        System.out.println("─".repeat(60));
        
        String qualidadeAr = avaliarQualidadeAr(mediaPM25, mediaCO2, mediaCO);
        System.out.println("📊 Classificação Geral: " + qualidadeAr);
        
        if (mediaPM25 > 35.0) {
            System.out.println("⚠️  ALERTA: Níveis de PM2.5 acima do recomendado (> 35 µg/m³)");
        }
        if (mediaCO2 > 1000.0) {
            System.out.println("⚠️  ALERTA: Níveis de CO2 elevados (> 1000 ppm)");
        }
        
        System.out.println("\n✅ Consulta 1 finalizada!\n");
    }
    
    // ═════════════════════════════════════════════════════════════
    //           CONSULTA 2: ANÁLISE DE SEGURANÇA E ANOMALIAS
    // ═════════════════════════════════════════════════════════════
    
    private static void realizarConsulta2() {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║       CONSULTA 2: ANÁLISE DE SEGURANÇA E ANOMALIAS        ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝\n");
        
        List<DadosColetados> dados = solicitarDadosHistoricos();
        
        if (dados == null || dados.isEmpty()) {
            System.out.println("❌ Não há dados disponíveis.\n");
            return;
        }
        
        // RELATÓRIO 2.1: Detecção de Temperaturas Críticas
        System.out.println("─".repeat(60));
        System.out.println("🚨 RELATÓRIO 2.1: DETECÇÃO DE TEMPERATURAS CRÍTICAS");
        System.out.println("─".repeat(60));
        
        List<DadosColetados> tempCriticas = dados.stream()
            .filter(d -> d.getTemperatura() > 40.0)
            .collect(Collectors.toList());
        
        if (tempCriticas.isEmpty()) {
            System.out.println("✅ Nenhuma temperatura crítica detectada (> 40°C)");
        } else {
            System.out.println("⚠️  Encontrados " + tempCriticas.size() + " registros com temperatura elevada:");
            tempCriticas.stream()
                .limit(10)
                .forEach(d -> System.out.printf("   • %s: %.1f°C em %s\n", 
                    d.getDispositivoId(), d.getTemperatura(), d.getTimestamp()));
        }
        
        // RELATÓRIO 2.2: Detecção de Anomalias Extremas (> 90°C)
        System.out.println("\n" + "─".repeat(60));
        System.out.println("🔥 RELATÓRIO 2.2: ANOMALIAS EXTREMAS (IDS/IPS)");
        System.out.println("─".repeat(60));
        
        List<DadosColetados> anomaliasExtremas = dados.stream()
            .filter(d -> d.getTemperatura() > 90.0)
            .collect(Collectors.toList());
        
        if (anomaliasExtremas.isEmpty()) {
            System.out.println("✅ Nenhuma anomalia extrema nos dados finais (> 90°C)");
            System.out.println("   → Possível indicação de bloqueio bem-sucedido pelo IPS");
        } else {
            System.out.println("🚨 CRÍTICO: Foram encontrados " + anomaliasExtremas.size() + " registros anômalos:");
            anomaliasExtremas.forEach(d -> {
                System.out.printf("   ⚠️  %s: %.1f°C | CO2: %.0f ppm | Timestamp: %s\n", 
                    d.getDispositivoId(), d.getTemperatura(), d.getCo2(), d.getTimestamp());
            });
            System.out.println("   → Estes dados podem ter passado antes do bloqueio do IPS");
        }
        
        // RELATÓRIO 2.3: Análise de Poluentes Críticos
        System.out.println("\n" + "─".repeat(60));
        System.out.println("💨 RELATÓRIO 2.3: ANÁLISE DE POLUENTES CRÍTICOS");
        System.out.println("─".repeat(60));
        
        long co2Critico = dados.stream().filter(d -> d.getCo2() > 1000.0).count();
        long pm25Critico = dados.stream().filter(d -> d.getPm25() > 50.0).count();
        long coCritico = dados.stream().filter(d -> d.getCo() > 9.0).count();
        
        System.out.println("📊 Contagem de registros acima dos limiares:");
        System.out.printf("   • CO2 > 1000 ppm: %d registros\n", co2Critico);
        System.out.printf("   • PM2.5 > 50 µg/m³: %d registros\n", pm25Critico);
        System.out.printf("   • CO > 9 ppm: %d registros\n", coCritico);
        
        // RELATÓRIO 2.4: Dispositivos Únicos
        System.out.println("\n" + "─".repeat(60));
        System.out.println("📱 RELATÓRIO 2.4: DISPOSITIVOS CONECTADOS");
        System.out.println("─".repeat(60));
        
        Set<String> dispositivosUnicos = dados.stream()
            .map(DadosColetados::getDispositivoId)
            .collect(Collectors.toSet());
        
        System.out.println("Total de dispositivos únicos: " + dispositivosUnicos.size());
        dispositivosUnicos.forEach(id -> {
            long count = dados.stream().filter(d -> d.getDispositivoId().equals(id)).count();
            System.out.printf("   • %s: %d registros\n", id, count);
        });
        
        System.out.println("\n✅ Consulta 2 finalizada!\n");
    }
    
    // ═════════════════════════════════════════════════════════════
    //                  RELATÓRIOS DE SEGURANÇA
    // ═════════════════════════════════════════════════════════════
    
    private static void exibirRelatoriosSeguranca() {
        System.out.println("\n" + "═".repeat(60));
        System.out.println("═".repeat(60));
        System.out.println("           RELATÓRIOS DO SISTEMA IDS/IPS");
        System.out.println("═".repeat(60));
        System.out.println("═".repeat(60) + "\n");
        
        // Relatório Estatístico Consolidado
        System.out.println(SistemaIDS.getRelatorioEstatistico());
        
        // Relatórios Detalhados
        List<String> relatoriosIds = SistemaIDS.getRelatorios();
        
        if (relatoriosIds.isEmpty()) {
            System.out.println("ℹ️  Nenhum alerta registrado pelo IDS/IPS durante a simulação.");
        } else {
            System.out.println("╔════════════════════════════════════════════════════════════╗");
            System.out.println("║              LOGS DETALHADOS DO IDS/IPS                    ║");
            System.out.println("╚════════════════════════════════════════════════════════════╝\n");
            
            System.out.println("Total de logs gerados: " + relatoriosIds.size());
            System.out.println("\n📋 Exibindo logs de anomalias:\n");
            
            relatoriosIds.stream()
                .filter(log -> log.contains("ANOMALIA"))
                .forEach(log -> {
                    System.out.println(log);
                    System.out.println();
                });
        }
        
        System.out.println("═".repeat(60));
        System.out.println("✅ ANÁLISE COMPLETA FINALIZADA!");
        System.out.println("═".repeat(60) + "\n");
    }
    
    // ═════════════════════════════════════════════════════════════
    //               MÉTODOS DE COMUNICAÇÃO HÍBRIDA
    // ═════════════════════════════════════════════════════════════

    private static AutenticacaoResponse solicitarAutenticacao(String id, String token, PublicKey serverPublicKey) {
        try (Socket socket = new Socket(ServidorDeAutenticacao.SERVER_IP, ServidorDeAutenticacao.AUTH_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            System.out.println("🔐 Conectando ao Servidor de Autenticação...");
            
            MensagemLogin login = new MensagemLogin(id, token, null);
            SecretKey aesKey = enviarRequisicaoHibrida(oos, login, serverPublicKey);
            
            System.out.println("📤 Credenciais enviadas (criptografadas)");
            
            return (AutenticacaoResponse) receberRespostaHibrida(ois, aesKey);
            
        } catch (ConnectException e) {
            System.err.println("❌ Servidor de Autenticação não está ativo.");
            return new AutenticacaoResponse(false, "Servidor Indisponível");
        } catch (Exception e) {
            System.err.println("❌ Erro na autenticação: " + e.getMessage());
            return new AutenticacaoResponse(false, "Erro de Comunicação");
        }
    }

    private static LocalizacaoResponse solicitarLocalizacao(String id, String tipoServico, PublicKey serverPublicKey) {
        try (Socket socket = new Socket(ServidorDeLocalizacao.SERVER_IP, ServidorDeLocalizacao.LOC_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("🗺️  Conectando ao Servidor de Localização...");
            
            MensagemLogin requisicao = new MensagemLogin(id, null, tipoServico);
            SecretKey aesKey = enviarRequisicaoHibrida(oos, requisicao, serverPublicKey);

            System.out.println("📤 Requisição de localização enviada: " + tipoServico);
            
            return (LocalizacaoResponse) receberRespostaHibrida(ois, aesKey);

        } catch (ConnectException e) {
            System.err.println("❌ Servidor de Localização não está ativo.");
            return new LocalizacaoResponse(false, null, 0);
        } catch (Exception e) {
            System.err.println("❌ Erro na localização: " + e.getMessage());
            return new LocalizacaoResponse(false, null, 0);
        }
    }
    
    private static List<DadosColetados> solicitarDadosHistoricos() {
        if (DATACENTER_IP == null || DATACENTER_CONSULTA_PORT == 0) {
            System.err.println("❌ Datacenter não localizado.");
            return null;
        }
        
        try (Socket socket = new Socket(DATACENTER_IP, DATACENTER_CONSULTA_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            
            System.out.println("📡 Conectando ao Datacenter...");
            
            // Envia requisição
            MensagemLogin reqVazia = new MensagemLogin(CLIENTE_ID, null, "CONSULTA");
            SecretKey aesKey = enviarRequisicaoHibrida(oos, reqVazia, datacenterPublicKey);
            
            System.out.println("📤 Requisição de dados históricos enviada");
            System.out.println("📥 Aguardando resposta criptografada...");
            
            // Recebe resposta
            @SuppressWarnings("unchecked")
            List<DadosColetados> dados = (List<DadosColetados>) receberRespostaHibrida(ois, aesKey);
            
            return dados;
            
        } catch (ConnectException e) {
            System.err.println("❌ Datacenter não está ativo na porta de consulta.");
            return null;
        } catch (Exception e) {
            System.err.println("❌ Erro na comunicação: " + e.getMessage());
            return null;
        }
    }
    
    private static SecretKey enviarRequisicaoHibrida(ObjectOutputStream oos, Serializable payload, PublicKey serverPublicKey) throws Exception {
        SecretKey aesKey = CriptografiaHibrida.generateAESKey();
        byte[] payloadSerializado = CriptografiaHibrida.serialize(payload);
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
    
    // ═════════════════════════════════════════════════════════════
    //                      MÉTODOS AUXILIARES
    // ═════════════════════════════════════════════════════════════
    
    private static String avaliarQualidadeAr(double pm25, double co2, double co) {
        if (pm25 < 12.0 && co2 < 800 && co < 5.0) {
            return "🟢 BOM - Ar de qualidade excelente";
        } else if (pm25 < 35.0 && co2 < 1000 && co < 7.0) {
            return "🟡 MODERADO - Qualidade aceitável";
        } else if (pm25 < 55.0 && co2 < 1500 && co < 9.0) {
            return "🟠 INADEQUADO - Grupos sensíveis devem ter cautela";
        } else {
            return "🔴 RUIM - Qualidade prejudicial à saúde";
        }
    }
}