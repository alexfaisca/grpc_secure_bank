package pt.ulisboa.ist.sirs.databaseserver.dto;

public record TicketDto(byte[] hash, byte[] sessionKey, byte[] sessionIV) {
}
