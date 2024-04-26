package pt.ulisboa.ist.sirs.authenticationserver.exceptions;

public class CannotInitializeClientCache  extends RuntimeException {
  public CannotInitializeClientCache(String serviceName) {
    super("Could not initialize cache for client: " + serviceName);
  }
}
