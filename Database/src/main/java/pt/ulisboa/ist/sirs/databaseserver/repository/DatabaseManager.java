package pt.ulisboa.ist.sirs.databaseserver.repository;

import org.hibernate.Session;
import org.hibernate.SessionFactory;

import pt.ulisboa.ist.sirs.databaseserver.dto.MovementDto;
import pt.ulisboa.ist.sirs.databaseserver.grpc.DatabaseService;
import pt.ulisboa.ist.sirs.databaseserver.repository.core.DatabaseTransaction;
import pt.ulisboa.ist.sirs.databaseserver.repository.core.HibernateUtil;
import pt.ulisboa.ist.sirs.databaseserver.repository.service.DatabaseState;
import pt.ulisboa.ist.sirs.databaseserver.repository.exceptions.WrongPasswordException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

public final class DatabaseManager {
  private abstract static class SimpleDatabaseTransaction<ObjectiveType> extends DatabaseTransaction {
    ObjectiveType yield;

    final void setTransactionYield(ObjectiveType yieldValue) {
      this.yield = yieldValue;
    }

    @Override
    public abstract void doInTransaction();

    final ObjectiveType yield() {
      execute();
      return yield;
    }
  }

  private final DatabaseService databaseService;
  private final DatabaseOperations databaseOperator;
  private final Session session;

  public DatabaseManager(DatabaseService service) {
    final SessionFactory sessionFactory = HibernateUtil.getSessionFactory();
    this.session = sessionFactory.openSession();
    this.databaseService = service;
    this.databaseOperator = new DatabaseState.DatabaseManagerBuilder(sessionFactory).build();
  }

  public DatabaseService getService() {
    return databaseService;
  }

  public void shutDown() {
    databaseService.delete();
    session.close();
    HibernateUtil.shutdown();
  }

  public void createAccount(List<String> usernames, byte[] password, BigDecimal initialDeposit,
      OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.CREATE_ACCOUNT, timestamp);
        databaseOperator.createAccount(usernames, password, initialDeposit);
      }
    }.yield();
  }

  public void deleteAccount(String username, byte[] password, OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.DELETE_ACCOUNT, timestamp);
        if (databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.deleteAccount(username);
      }
    }.yield();
  }

  public BigDecimal balance(String username, byte[] password, OffsetDateTime timestamp) {
    return new SimpleDatabaseTransaction<BigDecimal>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.BALANCE, timestamp);
        if (databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        setTransactionYield(databaseOperator.balance(username));
      }
    }.yield();
  }

  public List<MovementDto> getMovements(String username, byte[] password, OffsetDateTime timestamp) {
    return new SimpleDatabaseTransaction<List<MovementDto>>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.GET_MOVEMENTS, timestamp);
        if (databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        setTransactionYield(databaseOperator.getMovements(username));
      }
    }.yield();
  }

  @Deprecated
  public void addExpense(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.ADD_EXPENSE, timestamp);
        if (databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.addExpense(username, date, amount, description);
      }
    }.yield();
  }

  public void orderPayment(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      String recipient, OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        databaseOperator.registerOperation(DatabaseOperations.RequestType.ORDER_PAYMENT, timestamp);
        if (databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.orderPayment(username, date, amount, description, recipient);
      }
    }.yield();
  }
}
