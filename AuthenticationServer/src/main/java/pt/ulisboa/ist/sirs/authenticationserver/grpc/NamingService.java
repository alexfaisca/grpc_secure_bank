package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;

import javax.json.Json;
import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class NamingService {
  public static class NamingServerServiceBuilder {

    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;

    public NamingServerServiceBuilder(
        String service,
        String qualifier,
        String address,
        Integer port,
        boolean debug) {
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

  private final boolean debug;
  private final String address;
  private final Integer port;
  private final String service;
  private final String name;
  private final Map<String, List<OffsetDateTime>> timestamps = new HashMap<>();

  public NamingService(NamingServerServiceBuilder builder) {
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
}
