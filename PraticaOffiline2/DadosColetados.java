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
    private final double co;     // Monóxido de Carbono
    private final double no2;    // Dióxido de Nitrogênio
    private final double so2;    // Dióxido de Enxofre
    
    // Partículas 
    private final double pm25;   
    private final double pm10;   // Partículas Maiores
    
    // Condições Climáticas
    private final double temperatura; // Temperatura já existia
    private final double umidade;    // Umidade Relativa do Ar
    private final double radiacaoUV; // Índice de Radiação UV
    
    private final double ruido;      // Ruído Urbano (dB)
    
    // Construtor que gera dados aleatórios para simulação
    public DadosColetados(String dispositivoId) {
        this.dispositivoId = dispositivoId;
        this.timestamp = LocalDateTime.now();
        Random r = new Random();
        
        // Poluentes (ppm / ppb)
        this.co2 = 300 + (r.nextDouble() * 700);        // 300 a 1000 ppm
        this.co = r.nextDouble() * 10.0;                // 0 a 10 ppm
        this.no2 = 10 + (r.nextDouble() * 90);          // 10 a 100 ppb
        this.so2 = 5 + (r.nextDouble() * 45);           // 5 a 50 ppb

        // Partículas (µg/m³)
        this.pm25 = r.nextDouble() * 50;                // 0 a 50 µg/m³
        this.pm10 = 10 + (r.nextDouble() * 90);         // 10 a 100 µg/m³
        
        // Condições Climáticas
        this.temperatura = 15 + (r.nextDouble() * 25);  // 15 a 40 °C
        this.umidade = 40 + (r.nextDouble() * 50);      // 40 a 90 %
        this.radiacaoUV = r.nextDouble() * 12;          // 0 a 12 (Índice UV)
        
        this.ruido = 40 + (r.nextDouble() * 50);        // 40 a 90 dB
    }

    public String getDispositivoId() {
        return dispositivoId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public double getCo2() {
        return co2;
    }
    
    public double getCo() {
        return co;
    }

    public double getNo2() {
        return no2;
    }

    public double getSo2() {
        return so2;
    }
    
    public double getPm10() {
        return pm10;
    }

    public double getUmidade() {
        return umidade;
    }
    
    public double getRadiacaoUV() {
        return radiacaoUV;
    }
    
    public double getTemperatura() {
        return temperatura;
    }

    public double getRuido() {
        return ruido;
    }

    public double getPm25() {
        return pm25;
    }
    
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