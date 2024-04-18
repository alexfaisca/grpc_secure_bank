package pt.tecnico.sirs.databaseserver.repository;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import javax.json.JsonArrayBuilder;

public interface DatabaseOperations {
  void createAccount(List<String> usernames, byte[] password, BigDecimal initialDeposit, OffsetDateTime timestamp);

  void deleteAccount(String username, byte[] password, OffsetDateTime timestamp);

  boolean checkPassword(String username, byte[] password);

  BigDecimal balance(String username, byte[] password, OffsetDateTime timestamp);

  JsonArrayBuilder getMovements(String username, byte[] password, OffsetDateTime timestamp);

  @Deprecated
  void addExpense(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      OffsetDateTime timestamp);

  void orderPayment(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      String recipient, OffsetDateTime timestamp);
}
