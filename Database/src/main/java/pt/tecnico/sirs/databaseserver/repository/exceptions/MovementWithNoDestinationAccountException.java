package pt.tecnico.sirs.databaseserver.repository.exceptions;

public class MovementWithNoDestinationAccountException extends RuntimeException {
  public MovementWithNoDestinationAccountException() {
    super("Movement with no destination account");
  }
}
