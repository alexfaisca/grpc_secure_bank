package pt.ulisboa.ist.sirs.databaseserver.repository.exceptions;

public class NoSuchAccountException extends RuntimeException {
  public NoSuchAccountException() {
    super("No such account");
  }
}
