package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer;
import pt.ulisboa.ist.sirs.contract.bankserver.BankServer;
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

public class AuthenticationService {

  public static class AuthenticationServerServiceBuilder {

    private final boolean debug;
    private final String address;
    private final Integer port;
    private final String service;
    private final String name;
    private final CryptographicAuthenticationServerInterceptor crypto;

    public AuthenticationServerServiceBuilder(
        String service,
        String qualifier,
        String address,
        Integer port,
        CryptographicAuthenticationServerInterceptor crypto,
        boolean debug) {
      this.debug = debug;
      this.address = address;
      this.port = port;
      this.service = service;
      this.name = qualifier;
      this.crypto = crypto;
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
  private final CryptographicAuthenticationServerInterceptor crypto;
  private final List<OffsetDateTime> timestamps = new ArrayList<>();

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

  public List<OffsetDateTime> getTimestamps() {
    return this.timestamps;
  }

  public void addTimestamp(OffsetDateTime timestamp) {
    this.timestamps.add(timestamp);
  }

  public boolean oldTimestampString(OffsetDateTime timestamp) {
    return getTimestamps().contains(timestamp);
  }

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] alicePubKeyEnc) throws Exception {

    KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

    PublicKey clientPublic = bobKeyFac.generatePublic(x509KeySpec);

    /*
     * Bob gets the DH parameters associated with Alice's public key.
     * He must use the same parameters when he generates his own key
     * pair.
     */
    // Bob gets DH parameters from Alice's public Key
    DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)clientPublic).getParams();

    // Bob creates his own DH key pair
    KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
    bobKpairGen.initialize(dhParamFromAlicePubKey);
    KeyPair bobKpair = bobKpairGen.generateKeyPair();

    // Bob creates and initializes his DH KeyAgreement object
    KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
    bobKeyAgree.init(bobKpair.getPrivate());

    // Bob encodes his public key, and sends it over to Alice.
    byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

    /*
     * Bob uses Alice's public key for the first (and only) phase
     * of his version of the DH
     * protocol.
     */
    bobKeyAgree.doPhase(clientPublic, true);
    byte[] sharedSecret = bobKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");


    // Bob encrypts, using AES in CBC mode
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    cipher.doFinal(Base.generateRandom(Long.MAX_VALUE).toString().getBytes());

    // Retrieve the parameter that was used, and transfer it to Alice in encoded format
    byte[] encodedParams = cipher.getParameters().getEncoded();
    byte[] iv = Operations.generateIV(cipher.getParameters().hashCode(), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));
    Utils.writeBytesToFile(aesKey.getEncoded(), "resources/crypto/client/symmetricKey");
    Utils.writeBytesToFile(iv, "resources/crypto/client/iv");

    return new DiffieHellmanExchangeParameters(bobPubKeyEnc, encodedParams);
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
    System.out.println(crypto.popFromQueue(AuthenticationServer.AuthenticateRequest.class));
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
