package pt.ulisboa.ist.sirs.authenticationserver.dto;

public record DiffieHellmanExchangeParameters(byte[] publicKey, byte[] parameters) {
}
