package pt.ulisboa.ist.sirs.authenticationserver.exceptions;

public class CannotRemoveServerException extends Exception {
  public CannotRemoveServerException(String service, String address) {
    super("Cannot remove server at " + address + " from service " + service);
  }
}
