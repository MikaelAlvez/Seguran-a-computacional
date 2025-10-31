package MiniDNS;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.Scanner;

public class ClienteDescoberta {
    private static SecretKey chaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    private static SecretKey chaveHMAC = new SecretKeySpec("chaveHMACSegura123".getBytes(), "HmacSHA256");
    private static SecretKey chaveHMAC_ERRADA = new SecretKeySpec("chaveIncorreta123".getBytes(), "HmacSHA256");

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("\n🧠 Teste de segurança automático:");
        enviarConsultaComHMACErrado();
        enviarConsultaSemHMAC();
        Thread.sleep(2000);

        System.out.println("\n✅ Agora operando normalmente:");
        while (true) {
            System.out.print("\nDigite o serviço desejado (soma/multiplicacao) ou 'sair': ");
            String servico = sc.nextLine();
            if (servico.equalsIgnoreCase("sair")) break;

            System.out.print("Estratégia (roundrobin/random): ");
            String estrategia = sc.nextLine();

            String endereco = descobrirServico(servico, estrategia);
            if (endereco.equals("SERVIÇO_NÃO_ENCONTRADO")) {
                System.out.println("⚠️ Serviço não encontrado!");
                continue;
            }

            System.out.print("Digite o primeiro número: ");
            double a = sc.nextDouble();
            System.out.print("Digite o segundo número: ");
            double b = sc.nextDouble();
            sc.nextLine(); // limpar buffer

            executarOperacao(servico, endereco, a, b);
        }
    }

    private static void enviarConsultaComHMACErrado() throws Exception {
        Socket socket = new Socket("localhost", 6000);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String msg = "DISCOVER soma roundrobin";
        byte[] iv = CryptoUtils.gerarIV();
        String hmacErrado = CryptoUtils.gerarHMAC(msg, chaveHMAC_ERRADA);
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmacErrado, chaveAES, iv);
        System.out.println("🚨 Enviando DISCOVER com HMAC incorreto...");
        out.println(cifrado);
        socket.close();
    }

    private static void enviarConsultaSemHMAC() throws Exception {
        Socket socket = new Socket("localhost", 6000);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String msg = "DISCOVER soma roundrobin";
        byte[] iv = CryptoUtils.gerarIV();
        String cifrado = CryptoUtils.cifrar(msg, chaveAES, iv);
        System.out.println("🚫 Enviando DISCOVER sem HMAC...");
        out.println(cifrado);
        socket.close();
    }

    private static String descobrirServico(String servico, String estrategia) throws Exception {
        Socket socket = new Socket("localhost", 6000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        String msg = "DISCOVER " + servico + " " + estrategia;
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(msg, chaveHMAC);
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmac, chaveAES, iv);
        out.println(cifrado);

        String respostaCifrada = in.readLine();
        String decifrado = CryptoUtils.decifrar(respostaCifrada, chaveAES);
        String[] partes = decifrado.split("::");
        socket.close();
        return partes[0].split(" ")[2];
    }

    private static void executarOperacao(String servico, String endereco, double a, double b) throws Exception {
        int porta = endereco.equals("192.168.0.10") ? 6100 : 6200;
        Socket socket = new Socket("localhost", porta);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        String msg = "OPERACAO " + servico + " " + a + " " + b;
        byte[] iv = CryptoUtils.gerarIV();
        String hmac = CryptoUtils.gerarHMAC(msg, chaveHMAC);
        String cifrado = CryptoUtils.cifrar(msg + "::" + hmac, chaveAES, iv);
        out.println(cifrado);

        String respostaCifrada = in.readLine();
        String decifrado = CryptoUtils.decifrar(respostaCifrada, chaveAES);
        String[] partes = decifrado.split("::");
        System.out.println("📩 Resultado recebido: " + partes[0]);

        socket.close();
    }
}
