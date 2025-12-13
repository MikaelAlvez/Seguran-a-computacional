package PraticaOffiline2;

import javax.crypto.SecretKey;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class SistemaIDS {

    // Configuração da Borda
    private static final String BORDA_IP = "127.0.0.1";
    private static final int BORDA_CONTROL_PORT = 5556;

    // Armazenamento de relatórios
    private static final List<String> relatoriosIDS = Collections.synchronizedList(new LinkedList<>());
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    // Arquivo de log persistente
    private static final String LOG_FILE = "ids_alerts.log";
    
    // Contadores estatísticos
    private static int totalConexoes = 0;
    private static int totalAnomalias = 0;
    private static int totalBloqueios = 0;


    public static void sendAlert(DadosColetados dados, String ipOrigem, SecretKey aesKey) {
        synchronized (relatoriosIDS) {
            totalConexoes++;
        }
        
        String timestamp = LocalDateTime.now().format(FORMATTER);
        boolean anomaliaDetectada = false;
        StringBuilder logEntry = new StringBuilder();
        
        logEntry.append(String.format("[%s] 🛡️ IDS ANÁLISE:", timestamp));
        logEntry.append(String.format("\n   → Dispositivo: %s", dados.getDispositivoId()));
        logEntry.append(String.format("\n   → IP Origem: %s", ipOrigem));
        logEntry.append(String.format("\n   → Timestamp: %s", dados.getTimestamp()));
        
        // ===== REGRAS DE DETECÇÃO DE INTRUSÃO =====
        
        // REGRA 1: Temperatura Extrema (Principal Anomalia)
        if (dados.getTemperatura() > 90.0) {
            anomaliaDetectada = true;
            logEntry.append(String.format("\n   ⚠️  ANOMALIA 1: Temperatura EXTREMA detectada: %.1f°C (Limiar: 90°C)", 
                dados.getTemperatura()));
        }
        
        // REGRA 2: Níveis Críticos de CO2
        if (dados.getCo2() > 5000.0) {
            anomaliaDetectada = true;
            logEntry.append(String.format("\n   ⚠️  ANOMALIA 2: CO2 CRÍTICO: %.0f ppm (Limiar: 5000 ppm)", 
                dados.getCo2()));
        }
        
        // REGRA 3: Partículas PM2.5 Perigosas
        if (dados.getPm25() > 150.0) {
            anomaliaDetectada = true;
            logEntry.append(String.format("\n   ⚠️  ANOMALIA 3: PM2.5 PERIGOSO: %.1f µg/m³ (Limiar: 150 µg/m³)", 
                dados.getPm25()));
        }
        
        // REGRA 4: Dispositivos Inválidos (ID começando com "DI_")
        if (dados.getDispositivoId().startsWith("DI_")) {
            anomaliaDetectada = true;
            logEntry.append("\n   ⚠️  ANOMALIA 4: Dispositivo NÃO AUTORIZADO (ID inválido)");
        }
        
        if (dados.getCo() > 9.0 && dados.getNo2() > 90.0 && dados.getSo2() > 45.0) {
            anomaliaDetectada = true;
            logEntry.append("\n   ⚠️  ANOMALIA 5: MÚLTIPLOS POLUENTES em níveis críticos");
        }
        
        
        if (anomaliaDetectada) {
            synchronized (relatoriosIDS) {
                totalAnomalias++;
            }
            
            logEntry.append("\n   🚨 CLASSIFICAÇÃO: TRÁFEGO MALICIOSO / ANÔMALO");
            logEntry.append("\n   🔒 AÇÃO IPS: Iniciando bloqueio do dispositivo...");
            
            boolean bloqueioSucesso = enviarComandoDrop(dados.getDispositivoId());
            
            if (bloqueioSucesso) {
                synchronized (relatoriosIDS) {
                    totalBloqueios++;
                }
                logEntry.append("\n   ✅ IPS: Comando DROP enviado com SUCESSO para a Borda");
                logEntry.append(String.format("\n   ✅ Dispositivo %s foi BLOQUEADO pelo Firewall FW1", dados.getDispositivoId()));
            } else {
                logEntry.append("\n   ❌ IPS: FALHA ao enviar comando DROP (Borda pode estar offline)");
            }
            
        } else {
            logEntry.append("\n   ✅ Status: NORMAL - Parâmetros dentro dos limites aceitáveis");
            logEntry.append(String.format("\n   📊 Métricas: Temp=%.1f°C | CO2=%.0f ppm | PM2.5=%.1f µg/m³", 
                dados.getTemperatura(), dados.getCo2(), dados.getPm25()));
        }
        
        String logFinal = logEntry.toString();
        
        relatoriosIDS.add(logFinal);
        
        salvarLogEmArquivo(logFinal);
        
        if (anomaliaDetectada) {
            System.out.println("\n" + "═".repeat(60));
            System.out.println(logFinal);
            System.out.println("═".repeat(60) + "\n");
        }
    }

    private static boolean enviarComandoDrop(String dispositivoId) {
        try (Socket socket = new Socket(BORDA_IP, BORDA_CONTROL_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            String comando = "DROP:" + dispositivoId;
            out.println(comando);
            
            System.out.println("🚨 IPS → BORDA: Comando '" + comando + "' enviado para porta " + BORDA_CONTROL_PORT);
            
            return true;
            
        } catch (Exception e) {
            System.err.println("❌ IPS: Falha ao enviar comando DROP para a Borda: " + e.getMessage());
            return false;
        }
    }

    private static void salvarLogEmArquivo(String logEntry) {
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println(logEntry);
            pw.println("-".repeat(80));
        } catch (Exception e) {
            System.err.println("⚠️  Erro ao salvar log em arquivo: " + e.getMessage());
        }
    }

        public static List<String> getRelatorios() {
        return new LinkedList<>(relatoriosIDS);
    }
    
    public static String getRelatorioEstatistico() {
        StringBuilder relatorio = new StringBuilder();
        
        relatorio.append("\n╔════════════════════════════════════════════════════════════╗\n");
        relatorio.append("║          RELATÓRIO ESTATÍSTICO DO IDS/IPS                  ║\n");
        relatorio.append("╚════════════════════════════════════════════════════════════╝\n\n");
        
        relatorio.append("📊 ESTATÍSTICAS GERAIS:\n");
        relatorio.append(String.format("   • Total de Conexões Monitoradas: %d\n", totalConexoes));
        relatorio.append(String.format("   • Anomalias Detectadas: %d\n", totalAnomalias));
        relatorio.append(String.format("   • Bloqueios Executados (IPS): %d\n", totalBloqueios));
        
        if (totalConexoes > 0) {
            double percentualAnomalias = (totalAnomalias * 100.0) / totalConexoes;
            relatorio.append(String.format("   • Taxa de Anomalias: %.2f%%\n", percentualAnomalias));
        }
        
        relatorio.append("\n🛡️ REGRAS DE DETECÇÃO ATIVAS:\n");
        relatorio.append("   1. Temperatura Extrema (> 90°C)\n");
        relatorio.append("   2. CO2 Crítico (> 5000 ppm)\n");
        relatorio.append("   3. PM2.5 Perigoso (> 150 µg/m³)\n");
        relatorio.append("   4. Dispositivos Não Autorizados (ID inválido)\n");
        relatorio.append("   5. Múltiplos Poluentes Críticos (combinação)\n");
        
        relatorio.append("\n🔒 AÇÕES DE PREVENÇÃO (IPS):\n");
        relatorio.append("   • Comando DROP enviado para Borda (Firewall FW1)\n");
        relatorio.append("   • Bloqueio permanente do dispositivo na sessão\n");
        relatorio.append("   • Logs salvos em: " + LOG_FILE + "\n");
        
        relatorio.append("\n" + "═".repeat(60) + "\n");
        
        return relatorio.toString();
    }
    
    public static void limparRelatorios() {
        relatoriosIDS.clear();
        totalConexoes = 0;
        totalAnomalias = 0;
        totalBloqueios = 0;
        System.out.println("🗑️  Relatórios do IDS limpos.");
    }
}