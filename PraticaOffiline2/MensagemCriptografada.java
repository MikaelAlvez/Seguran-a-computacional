package PraticaOffiline2;

import java.io.Serializable;

public class MensagemCriptografada implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] chaveSimetricaCriptografada;
    private final byte[] dadosCriptografados;

    public MensagemCriptografada(byte[] chaveSimetricaCriptografada, byte[] dadosCriptografados) {
        this.chaveSimetricaCriptografada = chaveSimetricaCriptografada;
        this.dadosCriptografados = dadosCriptografados;
    }

    public byte[] getChaveSimetricaCriptografada() {
        return chaveSimetricaCriptografada;
    }

    public byte[] getDadosCriptografados() {
        return dadosCriptografados;
    }
}