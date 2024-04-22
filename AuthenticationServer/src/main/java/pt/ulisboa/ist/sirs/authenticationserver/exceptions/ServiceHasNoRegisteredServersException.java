package pt.ulisboa.ist.sirs.authenticationserver.exceptions;

public class ServiceHasNoRegisteredServersException extends Exception {
  public ServiceHasNoRegisteredServersException(String serviceName) {
    super("No servers registered for service " + serviceName);
  }
}