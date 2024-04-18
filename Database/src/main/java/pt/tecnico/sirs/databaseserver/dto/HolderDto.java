package pt.tecnico.sirs.databaseserver.dto;

import java.util.UUID;

public record HolderDto(String name, UUID accountNumber, UUID number) {
}
