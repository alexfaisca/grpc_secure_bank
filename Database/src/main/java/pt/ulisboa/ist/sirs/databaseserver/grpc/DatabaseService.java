package pt.ulisboa.ist.sirs.databaseserver.grpc;

import com.google.protobuf.ByteString;
import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.databaseserver.grpc.crypto.AuthenticationClientCryptographicManager;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public class DatabaseService {
  public static class DatabaseServiceBuilder {
    private final boolean debug;
    private final String service;
    private final String qualifier;
    private final String address;
    private final Integer port;
    private final AuthenticationClientCryptographicManager crypto;
    private final ChannelCredentials credentials;
    private ManagedChannel namingServerChannel;
    String namingServerAddress;
    Integer namingServerPort;

    public DatabaseServiceBuilder(
            String service,
            String qualifier,
            String address,
            Integer port,
            String namingServerAddress,
            Integer namingServerPort,
            String trustCertCollectionPath,
            AuthenticationClientCryptographicManager crypto,
            boolean debug) throws Exception {
      this.debug = debug;
      this.crypto = crypto;
      this.service = service;
      this.qualifier = qualifier;
      this.address = address;
      this.port = port;
      this.namingServerAddress = namingServerAddress;
      this.namingServerPort = namingServerPort;
      this.credentials = TlsChannelCredentials.newBuilder()
              .trustManager(new File(trustCertCollectionPath))
              .build();
    }

    public DatabaseService build() throws Exception {
      this.namingServerChannel = Grpc.newChannelBuilderForAddress(
              this.namingServerAddress,
              this.namingServerPort,
              this.credentials).build();
      return new DatabaseService(this);
    }
  }

  private final boolean debug;
  private final String service;
  private final String qualifier;
  private final String address;
  private final Integer port;
  private final AuthenticationClientCryptographicManager crypto;
  private final NamingServerServiceGrpc.NamingServerServiceBlockingStub stub;
  public DatabaseService(DatabaseServiceBuilder builder) throws Exception {
    this.debug = builder.debug;
    this.service = builder.service;
    this.qualifier = builder.qualifier;
    this.address = builder.address;
    this.port = builder.port;
    this.crypto = builder.crypto;
    this.stub = NamingServerServiceGrpc.newBlockingStub(builder.namingServerChannel);
    this.encryptedKeyExchange();
    this.register();
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

  public void encryptedKeyExchange() {
    try {
      crypto.initializeAuthCache();
      NamingServer.InitiateEncryptedKeyExchangeResponse initiateResponse = stub.initiateEncryptedKeyExchange(
        NamingServer.InitiateEncryptedKeyExchangeRequest.getDefaultInstance()
      );
      CertificateFactory certGen = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certGen.generateCertificate(
              new ByteArrayInputStream(initiateResponse.getServerCert().toByteArray())
      );
      cert.checkValidity();
      Utils.writeBytesToFile(
        cert.getPublicKey().getEncoded(), crypto.buildPublicKeyPath()
      );

      KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance("DH");
      clientKeypairGen.initialize(2048);
      KeyPair keyPair = clientKeypairGen.generateKeyPair();

      // Client creates and initializes her DH KeyAgreement object
      KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
      clientKeyAgree.init(keyPair.getPrivate());
      // Client encodes his public key, and sends it to server.
      byte[] ephemeralKey = Operations.generateSessionKey();
      byte[] ephemeralIV = Operations.generateIV(new SecureRandom().nextInt(), ephemeralKey, String.valueOf(new SecureRandom().nextDouble()));
      if (ephemeralKey == null || ephemeralIV == null)
        throw new RuntimeException("Ephemeral key generation went wrong.");
      // Merge ephemeral symmetric key and iv to encrypt using server public key
      byte[] keyIVConcat = new byte[ephemeralKey.length + ephemeralIV.length];
      System.arraycopy(ephemeralKey, 0, keyIVConcat, 0, ephemeralKey.length);
      System.arraycopy(ephemeralIV, 0, keyIVConcat, ephemeralKey.length, ephemeralIV.length);
      SecretKey secretKey = new SecretKeySpec(ephemeralKey, "AES");
      NamingServer.EncryptedKeyExchangeResponse serverResponse = stub.encryptedKeyExchange(
        NamingServer.EncryptedKeyExchangeRequest.newBuilder()
          .setClientParams(ByteString.copyFrom(Operations.encryptData(
            secretKey,
            keyPair.getPublic().getEncoded(),
            ephemeralIV
          ))).setClientCert(ByteString.copyFrom(Utils.readBytesFromFile(Base.CryptographicCore.getCertPath())))
          .setClientOps(ByteString.copyFrom(
            Operations.encryptDataAsymmetric(Base.readPublicKey(crypto.buildPublicKeyPath()), keyIVConcat)
      )).build());

      /*
       * Client uses server's public key for the first (and only) phase
       * of his part of the DH protocol.
       */
      JsonObject paramsJson = Utils.deserializeJson(Operations.decryptData(
        secretKey,
        serverResponse.getServerParams().toByteArray(),
        ephemeralIV
      ));
      KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Utils.hexToByte(paramsJson.getString("serverPublic")));
      PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

      clientKeyAgree.doPhase(serverPubKey, true);

      byte[] sharedSecret = clientKeyAgree.generateSecret();
      SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

      // Instantiate AlgorithmParameters object from parameter encoding
      // obtained from server
      AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
      aesParams.init(Utils.hexToByte(paramsJson.getString("parameters")));
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
      byte[] temp = Arrays.copyOfRange(aesParams.getEncoded(), 10, 14);
      byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

      Utils.writeBytesToFile(aesKey.getEncoded(), crypto.buildSessionKeyPath());
      Utils.writeBytesToFile(iv, crypto.buildIVPath());

      int random = Base.generateRandom(Integer.MAX_VALUE).intValue();
      int serverChallenge = Utils.byteArrayToInt(Operations.decryptData(
        Base.readSecretKey(crypto.buildSessionKeyPath()),
        serverResponse.getServerChallenge().toByteArray(),
        Base.readIv(crypto.buildIVPath())
      ));
      NamingServer.EncryptedKeyExchangeChallengeResponse challengeResponse = stub.encryptedKeyExchangeChallenge(
        NamingServer.EncryptedKeyExchangeChallengeRequest.newBuilder().setFinalizeClient(
          ByteString.copyFrom(Operations.encryptData(
            Base.readSecretKey(crypto.buildSessionKeyPath()),
            Utils.serializeJson(Json.createObjectBuilder()
              .add("serverChallenge",  serverChallenge + 1)
              .add("clientChallenge", random)
            .build()),
            Base.readIv(crypto.buildIVPath())
        ))).build()
      );

      int clientChallenge = Utils.byteArrayToInt(Operations.decryptData(
        Base.readSecretKey(crypto.buildSessionKeyPath()),
        challengeResponse.getFinalizeServer().toByteArray(),
        Base.readIv(crypto.buildIVPath())
      ));
      if (clientChallenge != random + 1)
        throw new TamperedMessageException();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void register() throws Exception {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Registering service");
    NamingServer.RegisterResponse ignore = stub.register(NamingServer.RegisterRequest.newBuilder()
      .setRequest(ByteString.copyFrom(Operations.encryptData(
        Base.readSecretKey(crypto.buildSessionKeyPath()),
        Utils.serializeJson(
          Utils.createJson(
            List.of("service", "address", "port", "qualifier"),
            List.of(NamingServer.Services.DatabaseServer.name(), getServerAddress(), getServerPort().toString(), getServerName()))),
        Utils.readBytesFromFile(crypto.buildIVPath())
    ))).build());
  }

  public void delete() throws Exception {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Deleting service");
    NamingServer.DeleteResponse ignore = stub.delete(NamingServer.DeleteRequest.newBuilder()
      .setRequest(ByteString.copyFrom(Operations.encryptData(
        Base.readSecretKey(crypto.buildSessionKeyPath()),
        Utils.serializeJson(
          Utils.createJson(
            List.of("service", "address", "port", "qualifier"),
            List.of(NamingServer.Services.DatabaseServer.name(), getServerAddress(), getServerPort().toString(), getServerName()))),
        Utils.readBytesFromFile(crypto.buildIVPath())
    ))).build());
  }
}
