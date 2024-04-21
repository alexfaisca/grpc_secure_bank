package pt.ulisboa.ist.sirs.authenticationserver.grpc;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
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

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] alicePubKeyEnc)
          throws Exception {
    String client = crypto.getDHClientHash();
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
    byte[] iv = Operations.generateIV(Base.byteArrayToInt(temp), aesKey.getEncoded(),
            Utils.byteToHex(sharedSecret));

    // Cache client crypto data
    crypto.initializeClientCache(client);
    Utils.writeBytesToFile(aesKey.getEncoded(), crypto.buildSymmetricKeyPath(client));
    Utils.writeBytesToFile(iv, crypto.buildIVPath(client));

    return new DiffieHellmanExchangeParameters(serverPubKeyEnc, encodedParams);
  }
}
