package pt.ulisboa.ist.sirs.authenticationserver.domain;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.enums.Service.Types;
import pt.ulisboa.ist.sirs.authenticationserver.exceptions.*;

import java.util.stream.Collectors;

import pt.ulisboa.ist.sirs.authenticationserver.grpc.NamingService;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;

import java.util.*;

public class NamingServerState {

  public static class NamingServerStateBuilder {
    private final boolean debug;
    private final NamingService service;

    public NamingServerStateBuilder(
            NamingServerCryptographicManager crypto,
            String serverService,
            String serverName,
            String host,
            Integer port,
            boolean debug) {
      this.debug = debug;
      this.service = new NamingService.NamingServerServiceBuilder(
              crypto,
              serverService,
              serverName,
              host,
              port,
              debug).build();
    }

    public NamingServerState build() {
      return new NamingServerState(this);
    }

  }

  public record ServerEntry(String server, String address, Integer port, String qualifier) {
  }

  private boolean debug;
  private final NamingService namingService;
  Map<Types, Map<String, ServerEntry>> services;

  public NamingServerState(NamingServerStateBuilder builder) {
    this.debug = builder.debug;
    this.namingService = builder.service;
    services = new HashMap<>();
    services.put(Types.BankServer, new HashMap<>());
    services.put(Types.DatabaseServer, new HashMap<>());
  }

  public boolean isDebug() {
    return this.debug;
  }

  private List<ServerEntry> getServerEntries(Types service) {
    return new ArrayList<ServerEntry>(this.services.get(service).values());
  }

  private ServerEntry getServerEntry(Types service, String qualifier) {
    return this.services.get(service).get(qualifier);
  }

  private void removeServerEntry(Types service, String qualifier) {
    this.services.get(service).remove(qualifier, this.services.get(service).get(qualifier));
  }

  private boolean checkServiceServerExists(Types service, String qualifier) {
    return services.get(service).containsKey(qualifier);
  }

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] pubKeyEnc, String client) {
    if (isDebug())
      System.out.println("\t\tAuthenticationServerState: diffieHellman initiate\n");
    try {
      return namingService.diffieHellmanExchange(pubKeyEnc, client);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void addServerEntry(Types service, String server, String address, Integer port, String qualifier) {
    if (!this.checkServiceServerExists(service, qualifier)) {
      if (this.isDebug())
        System.err.println("\t\tNamingServerState: Creating '" + service + "' service: '" + qualifier + "'");
      this.services.get(service).put(qualifier, new ServerEntry(server, address, port, qualifier));
    } else {
      if (this.isDebug())
        System.err.println("\t\tNamingServerState: '" + service + "' already exists.");
    }
  }

  public void register(Types service, String server, String address, Integer port, String qualifier)
      throws CannotRegisterServerException {
    if (!this.checkServiceServerExists(service, qualifier))
      this.addServerEntry(service, server, address, port, qualifier);
    if (this.isDebug())
      System.err.println(
          "\t\tNamingServerState: Adding '" + qualifier + "' at '" + address + "' to '" + service + "' service");
    this.getServerEntries(service).add(new ServerEntry(server, address, port, qualifier));
  }

  public List<ServerEntry> lookupServiceServers(Types service) {
    List<ServerEntry> s = getServerEntries(service);
    if (this.isDebug())
      System.err.println("\tNamingServerState: Found " + s.size() + " servers for service '" + service + "'");
    return s;
  }

  public List<ServerEntry> lookupServer(Types service, String qualifier) {
    List<ServerEntry> s = getServerEntries(service);
    if (this.isDebug())
      System.err.println("\tNamingServerState: Found " + s.size() + " servers for service '" + service + "'");
    if (s.isEmpty() || qualifier.isEmpty())
      return s;
    s = s.stream().filter(e -> e.qualifier().equals(qualifier)).collect(Collectors.toList());
    if (this.isDebug())
      System.err.println("\tAdminService: Found " + s.size() + " matching servers for qualifier '" + qualifier + "'");
    return s;
  }

  public void delete(Types service, String qualifier) throws CannotRemoveServerException {
    if (this.checkServiceServerExists(service, qualifier)) {
      if (this.isDebug())
        System.err.println("\t\tNamingServerState: Deleting server '" + qualifier + "'");

    } else
      throw new CannotRemoveServerException(service.toString(), qualifier);
  }
}
