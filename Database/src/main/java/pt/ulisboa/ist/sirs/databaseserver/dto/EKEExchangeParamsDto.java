package pt.ulisboa.ist.sirs.databaseserver.dto;

public record EKEExchangeParamsDto(byte[] clientPublic, byte[] clientEphemeral) {
}
