package pt.ulisboa.ist.sirs.databaseserver.dto;

import java.math.BigDecimal;
import java.util.UUID;

public record BankAccountDto(UUID number, byte[] password, BigDecimal balance, String currency) {
}
