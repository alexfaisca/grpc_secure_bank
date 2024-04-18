package pt.tecnico.sirs.databaseserver.repository.exceptions;

public class MovementWithNoFromAccountException extends RuntimeException {
  public MovementWithNoFromAccountException() {
    super("Movement with no from account");
  }
}
