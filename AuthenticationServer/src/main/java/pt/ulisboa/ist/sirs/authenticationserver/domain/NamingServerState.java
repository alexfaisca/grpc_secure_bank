package pt.ulisboa.ist.sirs.authenticationserver.domain;

import pt.ulisboa.ist.sirs.authenticationserver.enums.Service.Types;
import pt.ulisboa.ist.sirs.authenticationserver.exceptions.*;

import java.util.stream.Collectors;

import com.google.api.Advice;
import com.google.protobuf.Service;

import java.util.*;

public class NamingServerState {
  public final class ServerEntry {
    private final String address;
    private final Integer port;
    private final String qualifier;

    public ServerEntry(String address, Integer port, String qualifier) {
      this.address = address;
      this.port = port;
      this.qualifier = qualifier;
    }

    public String getAddress() {
      return address;
    }

    public Integer getPort() {
      return port;
    }

    public String getQualifier() {
      return qualifier;
    }
  }

  private boolean debug;

  Map<Types, Map<String, ServerEntry>> services;

  public NamingServerState() {
    this.debug = false;
    services = new HashMap<>();
    services.put(Types.BankServer, new HashMap<>());
    services.put(Types.DatabaseServer, new HashMap<>());
  }

  public NamingServerState(boolean debug) {
    this();
    this.debug = debug;
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
    this.services.get(service).remove(this.services.get(service).get(qualifier));
  }

  private boolean checkServiceServerExists(Types service, String qualifier) {
    return services.get(service).containsKey(qualifier);
  }

  private void addServerEntry(Types service, String address, Integer port, String qualifier) {
    if (!this.checkServiceServerExists(service, qualifier)) {
      if (this.isDebug())
        System.err.println("\t\tNamingServerState: Creating '" + service + "' service: '" + qualifier + "'");
      this.services.get(service).put(qualifier, new ServerEntry(address, port, qualifier));
    } else {
      if (this.isDebug())
        System.err.println("\t\tNamingServerState: '" + service + "' already exists.");
    }
  }

  public void register(Types service, String address, Integer port, String qualifier)
      throws CannotRegisterServerException {
    if (!this.checkServiceServerExists(service, qualifier))
      this.addServerEntry(service, address, port, qualifier);
    if (this.isDebug())
      System.err.println(
          "\t\tNamingServerState: Adding '" + qualifier + "' at '" + address + "' to '" + service + "' service");
    this.getServerEntries(service).add(new ServerEntry(address, port, qualifier));
  }

  public List<ServerEntry> lookup(Types service, String qualifier) {
    List<ServerEntry> s = getServerEntries(service);
    if (this.isDebug())
      System.err.println("\tNamingServerState: Found " + s.size() + " servers for service '" + service + "'");
    if (s.size() == 0 || qualifier.equals(""))
      return s;
    s = s.stream().filter(e -> e.getQualifier().equals(qualifier)).collect(Collectors.toList());
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
