package pt.ulisboa.ist.sirs.dto;

public record Ticket(byte[] sourceHash, byte[] sessionKey, byte[] sessionIV) {
}
