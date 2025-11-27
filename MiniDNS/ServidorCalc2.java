package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;

public class ServidorCalc2 {
    private static final String ENDERECO = "192.168.0.20"; // Simulado
    private static final int PORTA = 6200;

    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        // Registra o serviço no diretório
        Socket dir = new Socket("localhost", 6000);
        PrintWriter out = new PrintWriter(dir.getOutputStream(), true);
        String msg = "REGISTER multiplicacao " + ENDERECO;
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(msg, chaveHMAC);
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmac, chaveAES, iv);
        out.println(cifrado);
        dir.close();

        ServerSocket servidor = new ServerSocket(PORTA);
        System.out.println("🧮 ServidorCalc2 ativo (" + ENDERECO + ":" + PORTA + ")");

        while (true) {
            Socket cliente = servidor.accept();
            new Thread(() -> {
                try {
                    tratarCliente(cliente);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    private static void tratarCliente(Socket cliente) throws Exception {
        BufferedReader entrada = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
        PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true);
        String linha;
        while ((linha = entrada.readLine()) != null) {
            String decifrado = CryptoUtils.decifrar(linha, chaveAES);
            String[] partes = decifrado.split("::");
            String msg = partes[0];
            String[] dados = msg.split(" ");
            if (dados[0].equalsIgnoreCase("OPERACAO")) {
                String operacao = dados[1];
                double a = Double.parseDouble(dados[2]);
                double b = Double.parseDouble(dados[3]);
                double res = switch (operacao) {
                    case "soma" -> a + b;
                    case "subtracao" -> a - b;
                    case "multiplicacao" -> a * b;
                    case "divisao" -> b != 0 ? a / b : Double.NaN;
                    default -> 0;
                };
                String resposta = "RESULTADO " + res;
                byte[] iv = CryptoUtils.gerarIV();
                String hmac = CryptoUtils.gerarHMAC(resposta, chaveHMAC);
                String cifrado = CryptoUtils.cifrar(resposta + "::" + hmac, chaveAES, iv);
                saida.println(cifrado);
            }
        }
    }
}

