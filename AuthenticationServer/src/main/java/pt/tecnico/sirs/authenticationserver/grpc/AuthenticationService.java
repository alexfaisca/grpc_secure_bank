package pt.tecnico.sirs.authenticationserver.grpc;

import pt.tecnico.sirs.cryptology.Operations;
import pt.tecnico.sirs.cryptology.Base;
import pt.tecnico.sirs.utils.Utils;
import pt.tecnico.sirs.utils.exceptions.ReplayAttackException;

import javax.json.Json;
import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;

public class AuthenticationService {

  public static class AuthenticationServerServiceBuilder {

    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;

    public AuthenticationServerServiceBuilder(
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

    public AuthenticationService build() {
      return new AuthenticationService(this);
    }
  }

  private final boolean debug;
  private final String address;
  private final Integer port;
  private final String service;
  private final String name;
  private final List<OffsetDateTime> timestamps = new ArrayList<>();

  public AuthenticationService(AuthenticationServerServiceBuilder builder) {
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

  public List<OffsetDateTime> getTimestamps() {
    return this.timestamps;
  }

  public void addTimestamp(OffsetDateTime timestamp) {
    this.timestamps.add(timestamp);
  }

  public boolean oldTimestampString(OffsetDateTime timestamp) {
    return getTimestamps().contains(timestamp);
  }

  public synchronized byte[] authenticate(String source, String target, OffsetDateTime timestamp) throws Exception {
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: authenticating %s for %s\n", target, source);
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: validating timestamp %s\n", timestamp.toString());

    if (oldTimestampString(timestamp))
      throw new ReplayAttackException();
    addTimestamp(timestamp);

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: generating session key");

    String sessionKeyHex = Utils.byteToHex(Operations.generateSessionKey());

    String sessionIvHex = Utils.byteToHex(
        Operations.generateIV(
            new Random().nextInt(),
            Utils.hexToByte(sessionKeyHex),
            Utils.byteToHex(
                Operations.hash(ByteBuffer.allocate(Integer.BYTES).putInt(new Random().nextInt()).array()))));

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: generating target ticket");

    if (isDebug())
      System.out.println("\t\t\tAuthenticationService: serializing ticket");
    return Operations.encryptData(
        Base.readSecretKey("resources/crypto/client/symmetricKey"),
        Utils.serializeJson(
            Json.createObjectBuilder()
                .add("target", target)
                .add("timestampString", timestamp.toString())
                .add("sessionKey", sessionKeyHex)
                .add("sessionIv", sessionIvHex)
                .add("targetTicket", Utils.byteToHex(
                    Operations.encryptData(
                        Base.readSecretKey("resources/crypto/database/symmetricKey"),
                        Utils.serializeJson(Json.createObjectBuilder().add("source", source)
                            .add("sessionKey", sessionKeyHex).add("sessionIv", sessionIvHex).build()),
                        Base.readIv("resources/crypto/database/iv"))))
                .build()),
        Base.readIv("resources/crypto/client/iv"));
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
