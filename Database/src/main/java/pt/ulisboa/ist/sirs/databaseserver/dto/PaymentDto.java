package pt.ulisboa.ist.sirs.databaseserver.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

public record PaymentDto(UUID accountFrom, UUID accountTo, UUID paymentRef, BigDecimal amount, LocalDateTime requestDate, String description, Boolean authorized, Optional<UUID> movementRef) {
}
