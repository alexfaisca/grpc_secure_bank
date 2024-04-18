package pt.ulisboa.ist.sirs.databaseserver.repository.exceptions;

public class WrongPasswordException extends RuntimeException {
  public WrongPasswordException() {
    super("Wrong password");
  }
}
