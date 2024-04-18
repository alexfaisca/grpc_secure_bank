package pt.tecnico.sirs.databaseserver.repository.exceptions;

public class IllegalPaymentOrderBalance extends RuntimeException {
  public IllegalPaymentOrderBalance() {
    super("Negative value payment order not allowed");
  }
}
