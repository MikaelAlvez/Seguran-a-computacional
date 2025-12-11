package PraticaOffiline2;

import java.io.Serializable;

public class MensagemLogin implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String id;
    private final String token;
    private final String tipoServico; // Ex: "BORDA" ou "DATACENTER"

    public MensagemLogin(String id, String token, String tipoServico) {
        this.id = id;
        this.token = token;
        this.tipoServico = tipoServico;
    }

    public String getId() { return id; }
    public String getToken() { return token; }
    public String getTipoServico() { return tipoServico; }
}