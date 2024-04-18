package pt.ulisboa.ist.sirs.databaseserver.grpc;

public class DatabaseService {

  private final boolean debug;
  private final String service;
  private final String qualifier;
  private final String address;
  private final Integer port;

  public DatabaseService(String service, String name, String address, Integer port, boolean debug) {
    this.debug = debug;
    this.service = service;
    this.qualifier = name;
    this.address = address;
    this.port = port;
  }

  public String getServerServiceName() {
    return this.service;
  }

  public String getServerName() {
    return this.qualifier;
  }

  public String getServerAddress() {
    return this.address;
  }

  public Integer getServerPort() {
    return this.port;
  }

  public boolean isDebug() {
    return this.debug;
  }

  public void register() {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Registering service");
  }

  public void delete() {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Deleting service");
  }
}
