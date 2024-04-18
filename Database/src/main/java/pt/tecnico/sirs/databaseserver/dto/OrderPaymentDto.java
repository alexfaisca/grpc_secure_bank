package pt.tecnico.sirs.databaseserver.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

public record OrderPaymentDto(UUID accountFrom, UUID accountTo, LocalDateTime date, BigDecimal amount, String description, String  currency) {
}
