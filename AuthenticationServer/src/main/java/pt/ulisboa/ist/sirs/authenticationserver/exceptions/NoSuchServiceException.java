package pt.ulisboa.ist.sirs.authenticationserver.exceptions;

public class NoSuchServiceException extends Exception {
  public NoSuchServiceException(String serviceName) {
    super("No service entry found for service " + serviceName);
  }
}
