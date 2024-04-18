package pt.ulisboa.ist.sirs.databaseserver.repository.exceptions;

public class NotEnoughBalanceException extends RuntimeException {
  public NotEnoughBalanceException() {
    super("Not enough balance");
  }
}
