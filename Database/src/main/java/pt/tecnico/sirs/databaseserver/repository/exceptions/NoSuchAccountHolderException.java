package pt.tecnico.sirs.databaseserver.repository.exceptions;

public class NoSuchAccountHolderException extends RuntimeException {
  public NoSuchAccountHolderException() {
    super("No such account holder");
  }
}
