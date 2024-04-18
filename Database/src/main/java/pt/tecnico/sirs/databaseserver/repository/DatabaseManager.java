package pt.tecnico.sirs.databaseserver.repository;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import pt.tecnico.sirs.databaseserver.grpc.DatabaseService;
import pt.tecnico.sirs.databaseserver.repository.core.DatabaseTransaction;
import pt.tecnico.sirs.databaseserver.repository.core.HibernateUtil;
import pt.tecnico.sirs.databaseserver.repository.service.DatabaseState;
import pt.tecnico.sirs.databaseserver.repository.exceptions.WrongPasswordException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import javax.json.JsonArrayBuilder;

public final class DatabaseManager implements DatabaseOperations {
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
    databaseService.register();
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

  @Override
  public void createAccount(List<String> usernames, byte[] password, BigDecimal initialDeposit,
      OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        databaseOperator.createAccount(usernames, password, initialDeposit, timestamp);
      }
    }.yield();
  }

  @Override
  public void deleteAccount(String username, byte[] password, OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        if (!databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.deleteAccount(username, password, timestamp);
      }
    }.yield();
  }

  @Override
  public boolean checkPassword(String username, byte[] password) {
    return new SimpleDatabaseTransaction<Boolean>() {
      @Override
      public void doInTransaction() {
        setTransactionYield(databaseOperator.checkPassword(username, password));
      }
    }.yield();
  }

  @Override
  public BigDecimal balance(String username, byte[] password, OffsetDateTime timestamp) {
    return new SimpleDatabaseTransaction<BigDecimal>() {
      @Override
      public void doInTransaction() {
        if (!databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        setTransactionYield(databaseOperator.balance(username, password, timestamp));
      }
    }.yield();
  }

  @Override
  public JsonArrayBuilder getMovements(String username, byte[] password, OffsetDateTime timestamp) {
    return new SimpleDatabaseTransaction<JsonArrayBuilder>() {
      @Override
      public void doInTransaction() {
        if (!databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        setTransactionYield(databaseOperator.getMovements(username, password, timestamp));
      }
    }.yield();
  }

  @Override
  @Deprecated
  public void addExpense(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        if (!databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.addExpense(username, password, date, amount, description, timestamp);
      }
    }.yield();
  }

  @Override
  public void orderPayment(String username, byte[] password, LocalDateTime date, BigDecimal amount, String description,
      String recipient, OffsetDateTime timestamp) {
    new SimpleDatabaseTransaction<Void>() {
      @Override
      public void doInTransaction() {
        if (!databaseOperator.checkPassword(username, password))
          throw new WrongPasswordException();
        databaseOperator.orderPayment(username, password, date, amount, description, recipient, timestamp);
      }
    }.yield();
  }
}
