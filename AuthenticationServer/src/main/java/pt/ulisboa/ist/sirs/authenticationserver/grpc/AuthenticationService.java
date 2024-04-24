package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.AuthTicket;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;

import javax.json.Json;
import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;

public final class AuthenticationService extends AbstractAuthServerService {
  public static class AuthenticationServerServiceBuilder {

    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;
    private final AuthenticationServerCryptographicManager crypto;

    public AuthenticationServerServiceBuilder(
      AuthenticationServerCryptographicManager crypto,
      String service,
      String qualifier,
      String address,
      Integer port,
      boolean debug) {
      this.debug = debug;
      this.crypto = crypto;
      this.address = address;
      this.port = port;
      this.service = service;
      this.name = qualifier;
    }

    public AuthenticationService build() {
      return new AuthenticationService(this);
    }
  }

  private final boolean debug;
  private final String address;
  private final Integer port;
  private final String service;
  private final String name;
  private final AuthenticationServerCryptographicManager crypto;
  private final Map<String, List<OffsetDateTime>> timestamps = new HashMap<>();

  public AuthenticationService(AuthenticationServerServiceBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
    this.name = builder.name;
    this.address = builder.address;
    this.port = builder.port;
    this.crypto = builder.crypto;
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

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] clientPubEnc, String client) throws Exception {
    crypto.initializeClientCache(client);
    return super.diffieHellmanExchange(
      crypto.buildSymmetricKeyPath(client),
      crypto.buildIVPath(client),
      clientPubEnc
    );
  }

  public synchronized AuthTicket authenticate(
    String source, String qualifier, String target, String address, Integer port, OffsetDateTime timestamp
  ) throws Exception {
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: authenticating %s for %s\n", target, source);
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: validating timestamp %s\n", timestamp.toString());

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: generating session key");

    byte[] sessionKey = Operations.generateSessionKey();

    byte[] sessionIV = Operations.generateIV(
        new Random().nextInt(),
        sessionKey,
        Utils.byteToHex(
          Operations.hash(ByteBuffer.allocate(Long.BYTES).putLong(new Random().nextLong()).array()))
    );

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: generating target ticket");

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: serializing ticket");
    return new AuthTicket(qualifier, address, port, timestamp, sessionKey, sessionIV, Operations.encryptData(
      Base.readSecretKey(crypto.getTargetServerSymmetricKeyPath(target)),
      Utils.serializeJson(
        Json.createObjectBuilder()
          .add("source", source)
          .add("sessionKey", Utils.byteToHex(sessionKey))
          .add("sessionIV", Utils.byteToHex(sessionIV))
      .build()),
      Base.readIv(crypto.getTargetServerIVPath(target))
    ));
  }

  public void register() {
    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: register server");
  }

  public void delete() {
    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: delete server");
  }
}
