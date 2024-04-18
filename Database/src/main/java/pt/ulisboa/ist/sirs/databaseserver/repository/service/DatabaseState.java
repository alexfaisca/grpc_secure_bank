package pt.ulisboa.ist.sirs.databaseserver.repository.service;

import org.hibernate.SessionFactory;
import pt.ulisboa.ist.sirs.databaseserver.dto.BankAccountDto;
import pt.ulisboa.ist.sirs.databaseserver.dto.MovementDto;
import pt.ulisboa.ist.sirs.databaseserver.dto.PaymentDto;
import pt.ulisboa.ist.sirs.databaseserver.repository.DatabaseOperations;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.*;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl.*;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.*;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.engine.impl.*;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;

import javax.json.Json;
import javax.json.JsonArrayBuilder;

public class DatabaseState implements DatabaseOperations {
  public static final class DatabaseManagerBuilder {
    private final BankAccountService bankAccountService;
    private final MovementService movementService;
    private final PaymentService paymentService;

    public DatabaseManagerBuilder(SessionFactory databaseSession) {
      final ApprovalService approvalService = new ApprovalService(new ApprovalDAO(databaseSession));
      final BankAccountHolderService holderService = new BankAccountHolderService(
          new BankAccountHolderDAO(databaseSession));
      this.bankAccountService = new BankAccountService(
          new BankAccountDAO(databaseSession),
          holderService);
      this.movementService = new MovementService(
          new MovementDAO(databaseSession),
          bankAccountService);
      this.paymentService = new PaymentService(
          new PaymentDAO(databaseSession),
          approvalService,
          movementService,
          holderService,
          bankAccountService);
    }

    public DatabaseState build() {
      return new DatabaseState(this);
    }

  }

  private final BankAccountService bankAccountService;
  private final MovementService movementService;
  private final PaymentService paymentService;
  private final Map<RequestType, Set<OffsetDateTime>> timestamps = new HashMap<>();

  private DatabaseState(DatabaseManagerBuilder builder) {
    this.bankAccountService = builder.bankAccountService;
    this.movementService = builder.movementService;
    this.paymentService = builder.paymentService;
    for (RequestType type : RequestType.values())
      timestamps.put(type, new HashSet<>());
  }

  private Set<OffsetDateTime> getTimestamps(RequestType type) {
    return this.timestamps.get(type);
  }

  private void addTimestamp(RequestType type, OffsetDateTime timestamp) {
    this.timestamps.get(type).add(timestamp);
  }

  private boolean oldTimestampString(RequestType type, OffsetDateTime timestamp) {
    return getTimestamps(type).contains(timestamp);
  }

  @Override
  public void registerOperation(RequestType type, OffsetDateTime timestamp) {
    if (oldTimestampString(type, timestamp))
      throw new ReplayAttackException();
    addTimestamp(type, timestamp);
  }

  @Override
  public void createAccount(List<String> usernames, byte[] password, BigDecimal initialDeposit) {
    BankAccountDto ignore = bankAccountService.createAccount(usernames, password, initialDeposit);
  }

  @Override
  public void deleteAccount(String username) {
    bankAccountService.deleteAccount(username);
  }

  public boolean checkPassword(String username, byte[] password) {
    return bankAccountService.passwordCheck(username, password);
  }

  @Override
  public BigDecimal balance(String username) {
    return bankAccountService.getBalance(username);
  }

  @Override
  public JsonArrayBuilder getMovements(String username) {
    JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();

    for (MovementDto movementDto : movementService.getAccountMovements(username)) {
      arrayBuilder.add(
          Json.createObjectBuilder()
              .add("currency", movementDto.currency())
              .add("date", movementDto.date().toString())
              .add("value", movementDto.amount().toString())
              .add("description", movementDto.description()));
    }

    return arrayBuilder;
  }

  @Override
  @Deprecated
  public void addExpense(String username, LocalDateTime date, BigDecimal amount, String description) {
    MovementDto ignored = movementService.addMovement(username, date, amount, description);
  }

  @Override
  public void orderPayment(String username, LocalDateTime date, BigDecimal amount, String description,
      String recipient) {
    PaymentDto ignored = paymentService.orderPayment(username, date, amount, description, recipient);
  }

}
