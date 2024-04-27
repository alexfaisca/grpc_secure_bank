package pt.ulisboa.ist.sirs.databaseserver.grpc;

import com.google.protobuf.ByteString;
import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.enums.Enums;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.databaseserver.grpc.crypto.AuthenticationClientCryptographicManager;
import pt.ulisboa.ist.sirs.cryptology.EKEClient;
import pt.ulisboa.ist.sirs.databaseserver.grpc.crypto.NamingServerCryptographicStub;
import pt.ulisboa.ist.sirs.dto.EKEParams;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.File;

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
        boolean debug
    ) throws Exception {
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

    public DatabaseService build() {
      this.namingServerChannel = Grpc.newChannelBuilderForAddress(
        this.namingServerAddress,
        this.namingServerPort,
        this.credentials
      ).build();
      return new DatabaseService(this);
    }
  }

  private final boolean debug;
  private final String service;
  private final String qualifier;
  private final String address;
  private final Integer port;
  private final AuthenticationClientCryptographicManager crypto;
  private final NamingServerCryptographicStub stub;
  public DatabaseService(DatabaseServiceBuilder builder) {
    this.debug = builder.debug;
    this.service = builder.service;
    this.qualifier = builder.qualifier;
    this.address = builder.address;
    this.port = builder.port;
    this.crypto = builder.crypto;
    this.stub = new NamingServerCryptographicStub(builder.namingServerChannel, new AuthenticationClientCryptographicManager());
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
        NamingServer.Ack.getDefaultInstance()
      );
      crypto.validateServer(initiateResponse.getServerCert().toByteArray());

      EKEClient ekeClient = new EKEClient(crypto);
      EKEParams exchangeParams = ekeClient.encryptedKeyExchange();

      NamingServer.EncryptedKeyExchangeResponse serverResponse = stub.encryptedKeyExchange(
        NamingServer.EncryptedKeyExchangeRequest.newBuilder()
          .setClientParams(ByteString.copyFrom(exchangeParams.params()))
          .setClientCert(ByteString.copyFrom(Utils.readBytesFromFile(Base.CryptographicCore.getCertPath())))
          .setClientOps(ByteString.copyFrom(exchangeParams.publicKeySpecs()))
      .build());

      long serverChallenge = ekeClient.finalize(
        serverResponse.getServerParams().toByteArray(), serverResponse.getServerChallenge().toByteArray()
      );
      long random = Base.generateRandom(Long.MAX_VALUE);
      NamingServer.EncryptedKeyExchangeChallengeResponse challengeResponse = stub.encryptedKeyExchangeChallenge(
        NamingServer.EncryptedKeyExchangeChallengeRequest.newBuilder()
          .setClientChallenge(random)
          .setServerChallenge(serverChallenge + 1)
      .build());

      if (challengeResponse.getClientChallenge() != random + 1)
        throw new TamperedMessageException();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void register() {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Registering service");
    NamingServer.Ack ignore = stub.register(
      NamingServer.RegisterRequest.newBuilder()
        .setService(Enums.Services.DatabaseServer)
        .setAddress(getServerAddress())
        .setPort(getServerPort())
        .setQualifier(getServerName())
    .build());
  }

  public void delete() {
    if (isDebug())
      System.out.println("\t\t\tDatabaseService: Deleting service");
    NamingServer.Ack ignore = stub.delete(
      NamingServer.DeleteRequest.newBuilder()
      .setService(Enums.Services.DatabaseServer)
      .setQualifier(getServerName())
    .build());
  }
}
