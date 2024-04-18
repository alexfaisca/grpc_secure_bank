package pt.ulisboa.ist.sirs.databaseserver.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

public record MovementDto (UUID movementRef, UUID accountFrom, LocalDateTime date, BigDecimal amount, String description, String currency) {
}
