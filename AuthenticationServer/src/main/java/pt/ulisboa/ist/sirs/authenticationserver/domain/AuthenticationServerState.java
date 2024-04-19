package pt.ulisboa.ist.sirs.authenticationserver.domain;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.AuthenticationService;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;

import java.time.OffsetDateTime;

public class AuthenticationServerState {

  public static class AuthenticationServerStateBuilder {
    private final boolean debug;
    private final AuthenticationService service;

    public AuthenticationServerStateBuilder(
      AuthenticationServerCryptographicManager crypto,
      String serverService,
      String serverName,
      String host,
      Integer port,
      boolean debug) {
      this.debug = debug;
      this.service = new AuthenticationService.AuthenticationServerServiceBuilder(
        crypto,
        serverService,
        serverName,
        host,
        port,
        debug).build();
    }

    public AuthenticationServerState build() {
      return new AuthenticationServerState(this);
    }

  }

  private final boolean debug;
  private final AuthenticationService service;

  private AuthenticationServerState(AuthenticationServerStateBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
  }

  public String getAuthenticationServerService() {
    return service.getService();
  }

  public Integer getServerPort() {
    return service.getServerPort();
  }

  public String getServerAddress() {
    return service.getServerAddress();
  }

  public String getServerName() {
    return service.getServerName();
  }

  public boolean isDebug() {
    return debug;
  }

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] pubKeyEnc, String client, OffsetDateTime timestamp) {
    if (isDebug())
      System.out.printf("\t\tAuthenticationServerState: diffieHellman initiate\n");
    try {
      service.checkForReplayAttack(client, timestamp);
      return service.diffieHellmanExchange(pubKeyEnc);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized byte[] authenticate(String source, String target, String client, OffsetDateTime timestamp) {
    if (isDebug())
      System.out.printf("\t\tAuthenticationServerState: authenticating %s for %s\n", target, source);
    try {
      service.checkForReplayAttack(client, timestamp);
      return service.authenticate(source, target, timestamp);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void register() {
    service.register();
  }

  public void delete() {
    service.delete();
  }
}
