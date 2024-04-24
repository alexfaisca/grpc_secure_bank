package pt.ulisboa.ist.sirs.userclient.grpc;

import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.AuthenticationServerCryptographicStub;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.ClientCryptographicManager;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.DatabaseServerCryptographicStub;
import pt.ulisboa.ist.sirs.utils.Utils;
import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

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
    this.authenticate(OffsetDateTime.now().toString(), builder.credentials);
  }

  private void initializeStub(String address, Integer port, ChannelCredentials credentials) {
    Channel databaseChannel = Grpc.newChannelBuilderForAddress(
      address, port, credentials
    ).build();
    this.databaseServiceStub = new DatabaseServerCryptographicStub(databaseChannel, crypto);
  }

  public void diffieHellman() {
    try {
      KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance("DH");
      clientKeypairGen.initialize(2048);
      KeyPair keyPair = clientKeypairGen.generateKeyPair();

      // Client creates and initializes her DH KeyAgreement object
      KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
      clientKeyAgree.init(keyPair.getPrivate());

      // Client encodes his public key, and sends it to server.
      AuthenticationServer.DiffieHellmanExchangeResponse serverResponse = authenticationServerServiceStub.diffieHellmanExchange(
        AuthenticationServer.DiffieHellmanExchangeRequest.newBuilder().setClientPublic(ByteString.copyFrom(
          keyPair.getPublic().getEncoded()
      )).build());

      /*
       * Client uses server's public key for the first (and only) phase
       * of his part of the DH protocol.
       */
      KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
      X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverResponse.getServerPublic().toByteArray());
      PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

      clientKeyAgree.doPhase(serverPubKey, true);

      byte[] sharedSecret = clientKeyAgree.generateSecret();
      SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

      // Instantiate AlgorithmParameters object from parameter encoding
      // obtained from server
      AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
      aesParams.init(serverResponse.getParameters().toByteArray());
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
      byte[] temp = Arrays.copyOfRange(aesParams.getEncoded(), 10, 14);
      byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

      Utils.writeBytesToFile(aesKey.getEncoded(), ClientCryptographicManager.buildAuthKeyPath());
      Utils.writeBytesToFile(iv, ClientCryptographicManager.buildAuthIVPath());
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void authenticate(String timestampString, ChannelCredentials credentials) {
    try {
      // Needham-Schroeder step 1
      AuthenticationServer.AuthenticateResponse authTicket = authenticationServerServiceStub.authenticate(
        AuthenticationServer.AuthenticateRequest.newBuilder()
          .setSource("user")
          .setTarget("database")
          .setTimeStamp(timestampString)
      .build());

      // Needham-Schroeder step 2
      if (!authTicket.getTimeStamp().equals(timestampString))
        throw new TamperedMessageException();
      String address = authTicket.getAddress();
      Integer port = authTicket.getPort();

      initializeStub(address, port, credentials);

      // Save session key and session iv
      Utils.writeBytesToFile(
        authTicket.getSessionKey().toByteArray(), ClientCryptographicManager.buildSessionKeyPath()
      );
      Utils.writeBytesToFile(
        authTicket.getSessionIV().toByteArray(), ClientCryptographicManager.buildSessionIVPath()
      );

      // Needham-Schroeder step 3
      AuthenticateResponse authenticateDatabaseResponse = databaseServiceStub.authenticate(
        AuthenticateRequest.newBuilder()
          .setTimestamp(timestampString)
          .setTicket(authTicket.getTicket())
      .build());

      // Needham-Schroeder steps 4 and 5 (altered to receive server cert)
      int challenge = Base.generateRandom(Integer.MAX_VALUE).intValue();
      CertificateFactory certGen = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certGen.generateCertificate(
        new ByteArrayInputStream(authenticateDatabaseResponse.getServerCert().toByteArray())
      );
      cert.checkValidity();
      Utils.writeBytesToFile(
          cert.getPublicKey().getEncoded(), ClientCryptographicManager.buildSessionPublicKeyPath()
      );

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
          .setDate(amount)
          .setDate(description)
          .setDate(recipient)
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
