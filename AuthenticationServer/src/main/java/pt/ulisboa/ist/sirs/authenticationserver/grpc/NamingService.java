package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;

import java.io.File;
import java.time.OffsetDateTime;
import java.util.*;

public final class NamingService extends AbstractAuthServerService {
  public static class NamingServerServiceBuilder {
    private final NamingServerCryptographicManager crypto;
    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;

    public NamingServerServiceBuilder(
        NamingServerCryptographicManager crypto,
        String service,
        String qualifier,
        String address,
        Integer port,
        boolean debug) {
      this.crypto = crypto;
      this.debug = debug;
      this.address = address;
      this.port = port;
      this.service = service;
      this.name = qualifier;
    }

    public NamingService build() {
      return new NamingService(this);
    }
  }
  private final NamingServerCryptographicManager crypto;
  private final boolean debug;
  private final String address;
  private final Integer port;
  private final String service;
  private final String name;
  private final Map<String, List<OffsetDateTime>> timestamps = new HashMap<>();

  public NamingService(NamingServerServiceBuilder builder) {
    this.crypto = builder.crypto;
    this.debug = builder.debug;
    this.service = builder.service;
    this.name = builder.name;
    this.address = builder.address;
    this.port = builder.port;
  }

  public String getServerName() {
    return this.name;
  }

  public String getService() {
    return this.service;
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

  private void addTimestamp(String client, OffsetDateTime timestamp) {
    this.timestamps.get(client).add(timestamp);
  }

  private boolean oldTimestampString(String client, OffsetDateTime timestamp) {
    if (this.timestamps.get(client) == null) {
      this.timestamps.put(client, new ArrayList<>());
      return false;
    }
    return this.timestamps.get(client).contains(timestamp);
  }

  public synchronized void checkForReplayAttack(String client, OffsetDateTime timestamp) {
    if (oldTimestampString(client, timestamp))
      throw new ReplayAttackException();
    addTimestamp(client, timestamp);
  }

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] clientPubEnc) throws Exception {
    String client = crypto.getEKEClientHash();
    File clientDirectory = new File("resources/crypto/server/" + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");

    return super.diffieHellmanExchange(
            crypto.buildSymmetricKeyPath(client),
            crypto.buildIVPath(client),
            clientPubEnc
    );
  }
}
