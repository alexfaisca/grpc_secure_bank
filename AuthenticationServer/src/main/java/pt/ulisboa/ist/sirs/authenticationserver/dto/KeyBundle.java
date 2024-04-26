package pt.ulisboa.ist.sirs.authenticationserver.dto;

public record KeyBundle(byte[] ephemeralKey, byte[] ephemeralIV) {
}
