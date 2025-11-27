package PraticaOffiline2;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Cliente {
    private static final String DATACENTER_IP = "127.0.0.1";
    private static final int DATACENTER_CONSULTA_PORT = 8080; 
    
    public static void main(String[] args) throws Exception {
        System.out.println("--- CLIENTE INICIADO ---");
        System.out.println("Cliente Gestor_Urbano localizando e autenticando no Datacenter...");
        
        int tempoEsperaSegundos = 60; 
        System.out.println("Aguardando coleta de dados (Simulação por " + tempoEsperaSegundos + "s)...");
        try {
            TimeUnit.SECONDS.sleep(tempoEsperaSegundos);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        consultarEProcessarDados();
    }
    
    private static void consultarEProcessarDados() {
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
        
        System.out.println("\n--- ANÁLISE GESTOR URBANO ---");
        
        // RELATÓRIO: Médias Gerais (Ampliado)
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
            .filter(d -> d.getPm25() > 25.0 || d.getPm10() > 50.0) // PM10 > 50 µg/m³
            .count();
            
        if (alertasPM > (dados.size() * 0.1)) { // Se mais de 10% das leituras forem altas
            System.out.println("\n[3. ALERTA DE POLUIÇÃO POR PARTÍCULAS]");
            System.out.println("⚠️ " + alertasPM + " medições com PM2.5 ou PM10 elevado (Sugere restrição de atividades ao ar livre).");
        } else {
             System.out.println("\n[3. ALERTA DE POLUIÇÃO POR PARTÍCULAS] Status: OK. Nível de partículas sob controle.");
        }
        
        // ALERTA: Risco de Poluição Química (CO, NO2, SO2)
        // Usando limites da EPA (e.g., CO > 4.5 ppm é alto)
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
            .filter(d -> d.getUmidade() < 40.0 && d.getRadiacaoUV() > 8.0) // Umidade baixa E UV alto
            .count();
        
        if (alertasUmidade > 0) {
            System.out.println("\n[5. PREVISÃO: RISCO DE SAÚDE AMBIENTAL]");
            System.out.println("💧 Atenção! " + alertasUmidade + " ocorrências de baixa umidade e UV alto. (Recomendar hidratação e proteção solar).");
        } else {
            System.out.println("\n[5. PREVISÃO: RISCO DE SAÚDE AMBIENTAL] Status: OK. Condições climáticas estáveis.");
        }
    }
}