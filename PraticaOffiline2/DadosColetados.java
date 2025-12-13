package PraticaOffiline2;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Random;

public class DadosColetados implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private final String dispositivoId;
    private final LocalDateTime timestamp;
    
    // Poluentes Atmosféricos
    private final double co2;
    private final double co;
    private final double no2;
    private final double so2;
    
    // Partículas
    private final double pm25;
    private final double pm10;
    
    // Condições Climáticas
    private final double temperatura; 
    private final double umidade;
    private final double radiacaoUV;
    
    private final double ruido;
    
    // Construtor principal para dados normais
    public DadosColetados(String dispositivoId) {
        this(dispositivoId, false);
    }
    
    // Construtor auxiliar para simular dados normais ou anômalos
    public DadosColetados(String dispositivoId, boolean anomalia) {
        this.dispositivoId = dispositivoId;
        this.timestamp = LocalDateTime.now();
        Random r = new Random();
        
        // Poluentes (ppm / ppb)
        this.co2 = 300 + (r.nextDouble() * 700);
        this.co = r.nextDouble() * 10.0;
        this.no2 = 10 + (r.nextDouble() * 90);
        this.so2 = 5 + (r.nextDouble() * 45);

        // Partículas (µg/m³)
        this.pm25 = r.nextDouble() * 50;
        this.pm10 = 10 + (r.nextDouble() * 90);
        
        // Condições Climáticas
        if (anomalia) {
            // Anomalia: Temperatura muito alta (para ser detectada pelo IDS/IPS)
            this.temperatura = 95.0 + (r.nextDouble() * 10.0); // 95.0 a 105.0 °C
        } else {
            // Normal: 15 a 40 °C
            this.temperatura = 15 + (r.nextDouble() * 25); 
        }

        this.umidade = 40 + (r.nextDouble() * 50);
        this.radiacaoUV = r.nextDouble() * 12;
        
        this.ruido = 40 + (r.nextDouble() * 50);
    }

    // Getters e toString permanecem inalterados
    public String getDispositivoId() { return dispositivoId; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public double getCo2() { return co2; }
    public double getCo() { return co; }
    public double getNo2() { return no2; }
    public double getSo2() { return so2; }
    public double getPm10() { return pm10; }
    public double getUmidade() { return umidade; }
    public double getRadiacaoUV() { return radiacaoUV; }
    public double getTemperatura() { return temperatura; }
    public double getRuido() { return ruido; }
    public double getPm25() { return pm25; }
    
    @Override
    public String toString() {
        return String.format(
            "ID: %s | Tempo: %s\n" +
            "  Poluentes: CO2=%.1f ppm, CO=%.1f ppm, NO2=%.1f ppb, SO2=%.1f ppb\n" +
            "  Partículas: PM2.5=%.1f µg/m³, PM10=%.1f µg/m³\n" +
            "  Clima: Temp=%.1f °C, Umid=%.1f %%, UV=%.1f\n" +
            "  Ruído: %.1f dB",
            dispositivoId, 
            timestamp.toString(),
            co2, co, no2, so2,
            pm25, pm10,
            temperatura, umidade, radiacaoUV,
            ruido
        );
    }
}