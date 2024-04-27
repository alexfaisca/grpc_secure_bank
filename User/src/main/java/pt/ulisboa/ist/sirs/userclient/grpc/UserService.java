package pt.ulisboa.ist.sirs.userclient.grpc;

import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.enums.Enums;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.AuthenticationServerCryptographicStub;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.ClientCryptographicManager;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.DatabaseServerCryptographicStub;
import pt.ulisboa.ist.sirs.cryptology.DiffieHellmanClient;
import pt.ulisboa.ist.sirs.utils.Utils;
import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.*;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class UserService {

  public static class UserServiceBuilder {
    private final boolean debug;
    private final ClientCryptographicManager crypto;
    private final ChannelCredentials credentials;
    private ManagedChannel authenticationServerChannel;
    String authenticationServerAddress;
    Integer authenticationServerPort;

    public UserServiceBuilder(
        String authenticationServerAddress,
        Integer authenticationServerPort,
        String trustCertCollectionPath,
        ClientCryptographicManager crypto,
        boolean debug
    ) throws Exception {
      this.debug = debug;
      this.crypto = crypto;
      this.authenticationServerAddress = authenticationServerAddress;
      this.authenticationServerPort = authenticationServerPort;
      this.credentials = TlsChannelCredentials.newBuilder().trustManager(new File(trustCertCollectionPath)).build();
    }

    public UserService build() {
      this.authenticationServerChannel = Grpc.newChannelBuilderForAddress(
        this.authenticationServerAddress, this.authenticationServerPort, this.credentials
      ).build();
      return new UserService(this);
    }
  }

  private final boolean debug;
  private final ClientCryptographicManager crypto;
  private final AuthenticationServerCryptographicStub authenticationServerServiceStub;
  private DatabaseServerCryptographicStub databaseServiceStub;
  private final Logger logger;

  private UserService(UserServiceBuilder builder) {
    this.crypto = builder.crypto;
    this.debug = builder.debug;
    this.logger = Logger.getLogger("UserService");
    this.authenticationServerServiceStub = new AuthenticationServerCryptographicStub(
      builder.authenticationServerChannel, crypto
    );
    this.diffieHellman();
    this.authenticate(this.lookup(), OffsetDateTime.now().toString(), builder.credentials);
  }

  private void initializeStub(String address, Integer port, ChannelCredentials credentials) {
    Channel databaseChannel = Grpc.newChannelBuilderForAddress(
      address, port, credentials
    ).build();
    this.databaseServiceStub = new DatabaseServerCryptographicStub(databaseChannel, crypto);
  }

  public void diffieHellman() {
    try {
      DiffieHellmanClient dhClient = new DiffieHellmanClient(crypto);
      // Client encodes his public key, and sends it to server.
      AuthenticationServer.DiffieHellmanExchangeResponse serverResponse = authenticationServerServiceStub.diffieHellmanExchange(
        AuthenticationServer.DiffieHellmanExchangeRequest.newBuilder().setClientPublic(ByteString.copyFrom(
          dhClient.diffieHellmanInitialize()
      )).build());
      dhClient.diffieHellmanFinish(
        serverResponse.getServerPublic().toByteArray(), serverResponse.getParameters().toByteArray()
      );
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public String lookup() {
    Enums.Services services = Enums.Services.DatabaseServer;
    AuthenticationServer.LookupResponse lookupResponse = authenticationServerServiceStub.lookup(
      AuthenticationServer.LookupRequest.newBuilder().setService(services).build()
    );
    if (lookupResponse.getServersList().isEmpty())
      throw new RuntimeException("Could not find any service server for service '" + services.name() + "'");
    return lookupResponse.getServersList().get(0).getQualifier();
  }

  public void authenticate(String qualifier, String timestampString, ChannelCredentials credentials) {
    try {
      // Needham-Schroeder step 1
      AuthenticationServer.AuthenticateResponse authTicket = authenticationServerServiceStub.authenticate(
        AuthenticationServer.AuthenticateRequest.newBuilder()
          .setSource("user")
          .setTarget(qualifier)
          .setTimeStamp(timestampString)
      .build());

      // Needham-Schroeder step 2
      if (!authTicket.getTimeStamp().equals(timestampString))
        throw new TamperedMessageException();

      initializeStub(authTicket.getAddress(), authTicket.getPort(), credentials);

      // Save session key and session iv
      crypto.initializeSession(authTicket.getSessionKey().toByteArray(), authTicket.getSessionIV().toByteArray());

      // Needham-Schroeder step 3
      AuthenticateResponse authenticateDatabaseResponse = databaseServiceStub.authenticate(
        AuthenticateRequest.newBuilder()
          .setTimestamp(timestampString)
          .setTicket(authTicket.getTicket())
      .build());

      // Needham-Schroeder steps 4 and 5 (altered to receive server cert)
      int challenge = Base.generateRandom(Integer.MAX_VALUE).intValue();
      crypto.validateSession(authenticateDatabaseResponse.getServerCert().toByteArray());

      StillAliveResponse stillAliveResponse = databaseServiceStub.stillAlive(
        StillAliveRequest.newBuilder()
          .setClientChallenge(challenge)
          .setServerChallenge(authenticateDatabaseResponse.getServerChallenge() - 1)
          .setPublicKey(
            ByteString.copyFrom(Utils.readBytesFromFile(ClientCryptographicManager.buildSelfPublicKeyPath()))
      ).build());

      if(stillAliveResponse.getClientChallenge() != challenge + 1)
        throw new RuntimeException("Still alive challenge failed");

    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void createAccount(List<String> usernames, List<String> passwords, String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding create account request");
      if (passwords.isEmpty())
        throw new RuntimeException("Please provide the necessary information.");
      String password = passwords.get(0);

      Ack ignored = databaseServiceStub.createAccount(
        CreateAccountRequest.newBuilder()
          .addAllNames(usernames)
          .setPassword(ByteString.copyFrom(crypto.encryptPassword(password)))
          .setTimestamp(timestampString)
      .build());

      if (debug)
        System.out.println("\tUserService: processing create account response");
    } catch (StatusRuntimeException e) {
      System.out.println(e.getMessage());
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void deleteAccount(String username, String password, String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding delete account request");

      Ack ignored = databaseServiceStub.deleteAccount(
        DeleteAccountRequest.newBuilder()
          .setName(username)
          .setPassword(ByteString.copyFrom(crypto.encryptPassword(password)))
          .setTimestamp(timestampString)
      .build());

      if (debug)
        System.out.println("\tUserService: processing delete account response");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void balance(String username, String password, String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding delete account request");

      BalanceResponse balanceResponse = databaseServiceStub.balance(
        BalanceRequest.newBuilder()
          .setName(username)
          .setPassword(ByteString.copyFrom(crypto.encryptPassword(password)))
          .setTimestamp(timestampString)
      .build());

      if (debug)
        System.out.println("\tUserService: processing balance response");
      System.out.println(balanceResponse.getAmount());
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void getMovements(String username, String password, String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding show expenses request");

      GetMovementsResponse getAccountMovementsResponse = databaseServiceStub.getMovements(
        GetMovementsRequest.newBuilder()
          .setName(username)
          .setPassword(ByteString.copyFrom(crypto.encryptPassword(password)))
          .setTimestamp(timestampString)
      .build());

      for (GetMovementsResponse.Movement m: getAccountMovementsResponse.getMovementsList())
        System.out.printf(
          "Movement %s\n\tCurrency: %s\n\tDate: %s\n\tValue: %s\n\tDescription: %s\n",
          m.getId(),
          m.getCurrency(),
          m.getDate(),
          m.getValue(),
          m.getDescription()
      );
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void paymentOrder(String username, String password, String date, String amount, String description,
      String recipient, String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding payment order request");

      Ack ignored = databaseServiceStub.orderPayment(
        OrderPaymentRequest.newBuilder()
          .setName(username)
          .setPassword(ByteString.copyFrom(crypto.encryptPassword(password)))
          .setDate(date)
          .setAmount(amount)
          .setDescription(description)
          .setRecipient(recipient)
          .setTimestamp(timestampString)
      .build());

      if (debug)
        System.out.println("\tUserService: processing payment order response");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

}
