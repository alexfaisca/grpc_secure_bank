package pt.ulisboa.ist.sirs.databaseserver.repository.exceptions;

public class NoSuchAccountHolderException extends RuntimeException {
  public NoSuchAccountHolderException() {
    super("No such account holder");
  }
}
