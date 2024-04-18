package pt.ulisboa.ist.sirs.databaseserver.repository;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import javax.json.JsonArrayBuilder;

public interface DatabaseOperations {

  enum RequestType {
    CREATE_ACCOUNT, DELETE_ACCOUNT, BALANCE, GET_MOVEMENTS, ADD_EXPENSE, ORDER_PAYMENT
  }

  void registerOperation(RequestType type, OffsetDateTime timestamp);

  void createAccount(List<String> usernames, byte[] password, BigDecimal initialDeposit);

  void deleteAccount(String username);

  boolean checkPassword(String username, byte[] password);

  BigDecimal balance(String username);

  JsonArrayBuilder getMovements(String username);

  @Deprecated
  void addExpense(String username, LocalDateTime date, BigDecimal amount, String description);

  void orderPayment(String username, LocalDateTime date, BigDecimal amount, String description,
      String recipient);
}
