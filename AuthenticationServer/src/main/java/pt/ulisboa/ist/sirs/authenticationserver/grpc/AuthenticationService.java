package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;

import javax.json.Json;
import java.io.File;
import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

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
  private final Map<String, List<OffsetDateTime>> timestamps = new HashMap<>();

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

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] alicePubKeyEnc, String client)
      throws Exception {

    KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

    PublicKey clientPublic = serverKeyFac.generatePublic(x509KeySpec);

    // Server gets DH parameters from client's public Key
    DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey) clientPublic).getParams();

    // Server creates his own DH key pair
    KeyPairGenerator serverKeypairGen = KeyPairGenerator.getInstance("DH");
    serverKeypairGen.initialize(dhParamFromClientPubKey);
    KeyPair serverKeypair = serverKeypairGen.generateKeyPair();

    // Server creates and initializes his DH KeyAgreement object
    KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
    serverKeyAgree.init(serverKeypair.getPrivate());

    // Server encodes his public key, and sends it to client.
    byte[] serverPubKeyEnc = serverKeypair.getPublic().getEncoded();

    /*
     * Server uses client's public key for the first (and only) phase
     * of his part of the DH protocol.
     */
    serverKeyAgree.doPhase(clientPublic, true);
    byte[] sharedSecret = serverKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

    // Server encrypts, using AES in CBC mode
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    cipher.doFinal(Base.generateRandom(Long.MAX_VALUE).toString().getBytes());

    // Retrieve the parameter that was used, and transfer it to Alice in encoded
    // format
    byte[] encodedParams = cipher.getParameters().getEncoded();
    byte[] temp = Arrays.copyOfRange(encodedParams, 10, 14);
    Integer number =((temp[0] & 0xFF) << 24) |
            ((temp[1] & 0xFF) << 16) |
            ((temp[2] & 0xFF) << 8) |
            ((temp[3] & 0xFF));
    byte[] iv = Operations.generateIV(number, aesKey.getEncoded(),
        Utils.byteToHex(sharedSecret));
    File clientDirectory = new File("resources/crypto/" + client + "/");
    if (!clientDirectory.exists())
        if (!clientDirectory.mkdirs())
          throw new RuntimeException("Could not store client key");

    Utils.writeBytesToFile(aesKey.getEncoded(), "resources/crypto/" + client + "/symmetricKey");
    Utils.writeBytesToFile(iv, "resources/crypto/" + client + "/iv");

    return new DiffieHellmanExchangeParameters(serverPubKeyEnc, encodedParams);
  }

  public synchronized byte[] authenticate(String source, String target, String client, OffsetDateTime timestamp)
      throws Exception {
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: authenticating %s for %s\n", target, source);
    if (isDebug())
      System.out.printf("\t\t\tAuthenticationService: validating timestamp %s\n", timestamp.toString());

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
        Base.readSecretKey("resources/crypto/" + client + "/symmetricKey"),
        Utils.serializeJson(
            Json.createObjectBuilder()
                .add("target", target)
                .add("timestampString", timestamp.toString())
                .add("sessionKey", sessionKeyHex)
                .add("sessionIv", sessionIvHex)
                .add("targetTicket", Utils.byteToHex(
                    Operations.encryptData(
                        Base.readSecretKey("resources/crypto/database/symmetricKey"),
                        Utils.serializeJson(
                            Json.createObjectBuilder()
                            .add("source", source)
                            .add("sessionKey", sessionKeyHex).add("sessionIv", sessionIvHex).build()),
                        Base.readIv("resources/crypto/database/iv"))))
                .build()),
        Base.readIv("resources/crypto/" + client + "/iv"));
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
