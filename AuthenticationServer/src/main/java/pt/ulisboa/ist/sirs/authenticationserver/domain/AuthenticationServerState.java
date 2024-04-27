package pt.ulisboa.ist.sirs.authenticationserver.domain;

import pt.ulisboa.ist.sirs.authenticationserver.dto.AuthTicket;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.dto.ServerIdentity;
import pt.ulisboa.ist.sirs.authenticationserver.dto.TargetServer;
import pt.ulisboa.ist.sirs.authenticationserver.enums.Service;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.AuthenticationService;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;

import java.time.OffsetDateTime;
import java.util.List;

public class AuthenticationServerState {

  public static class AuthenticationServerStateBuilder {
    private final boolean debug;
    private final AuthenticationService service;
    private final NamingServerState namingServerState;

    public AuthenticationServerStateBuilder(
      AuthenticationServerCryptographicManager crypto,
      NamingServerState namingServerState,
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
      this.namingServerState = namingServerState;
    }

    public AuthenticationServerState build() {
      return new AuthenticationServerState(this);
    }

  }

  private final boolean debug;
  private final AuthenticationService service;
  private final NamingServerState namingServerState;

  private AuthenticationServerState(AuthenticationServerStateBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
    this.namingServerState = builder.namingServerState;
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

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] pubKeyEnc, String client) {
    if (isDebug())
      System.out.println("\t\tAuthenticationServerState: diffieHellman initiate\n");
    try {
      return service.diffieHellmanExchange(pubKeyEnc, client);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public synchronized List<ServerIdentity> lookup(Service.Types service) {
    return namingServerState.lookupServiceServers(service).stream()
      .map(s -> new ServerIdentity(s.qualifier())).toList();
  }

  public synchronized AuthTicket authenticate(String source, String target, String client, OffsetDateTime timestamp) {
    if (isDebug())
      System.out.printf("\t\tAuthenticationServerState: authenticating %s\n", source);
    try {
      service.checkForReplayAttack(client, timestamp);
      TargetServer targetServer = namingServerState.getServerEntry(Service.Types.DatabaseServer, target);
      return service.authenticate(
        source, targetServer.qualifier(), targetServer.server(), targetServer.address(), targetServer.port(), timestamp
      );
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
