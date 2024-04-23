package pt.ulisboa.ist.sirs.userclient.grpc;

import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.ClientCryptographicManager;
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
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;

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
  private final AuthenticationServerServiceGrpc.AuthenticationServerServiceBlockingStub authenticationServerServiceStub;
  private DatabaseServiceGrpc.DatabaseServiceBlockingStub databaseServiceStub;
  private final Logger logger;

  private UserService(UserServiceBuilder builder) {
    this.crypto = builder.crypto;
    this.debug = builder.debug;
    this.logger = Logger.getLogger("UserService");
    this.authenticationServerServiceStub = AuthenticationServerServiceGrpc.newBlockingStub(
      builder.authenticationServerChannel
    );
    this.diffieHellman();
    this.authenticate(OffsetDateTime.now().toString(), builder.credentials);
  }

  private void initializeStub(String address, Integer port, ChannelCredentials credentials) {
    Channel databaseChannel = Grpc.newChannelBuilderForAddress(
      address, port, credentials
    ).build();
    this.databaseServiceStub = DatabaseServiceGrpc.newBlockingStub(databaseChannel);
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

      File clientDirectory = new File("resources/crypto/client/");
      if (!clientDirectory.exists())
        if (!clientDirectory.mkdirs())
          throw new RuntimeException("Could not store client key");
      Utils.writeBytesToFile(aesKey.getEncoded(), "resources/crypto/client/symmetricKey");
      Utils.writeBytesToFile(iv, "resources/crypto/client/iv");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void authenticate(String timestampString, ChannelCredentials credentials) {
    try {
      // Needham-Schroeder step 1
      AuthenticationServer.AuthenticateResponse ticketResponse = authenticationServerServiceStub.authenticate(
        AuthenticationServer.AuthenticateRequest.newBuilder().setRequest(
          ByteString.copyFrom(
            Operations.encryptData(
              Base.readSecretKey("resources/crypto/client/symmetricKey"),
              Utils.serializeJson(
                Utils.createJson(
                  List.of("source", "target", "timestampString"),
                  List.of("user", "database", timestampString))),
              Utils.readBytesFromFile("resources/crypto/client/iv")
      ))).build());

      // Needham-Schroeder step 2
      JsonObject ticketJson = Utils.deserializeJson(Operations.decryptData(
        Base.readSecretKey("resources/crypto/client/symmetricKey"),
        ticketResponse.getResponse().toByteArray(),
        Base.readIv("resources/crypto/client/iv")
      ));

      if (!ticketJson.getString("timestampString").equals(timestampString))
        throw new TamperedMessageException();
      String address = ticketJson.getString("address");
      Integer port = ticketJson.getInt("port");

      initializeStub(address, port, credentials);
      // Save session key and session iv
      File clientDirectory = new File("resources/crypto/session/");
      if (!clientDirectory.exists())
        if (!clientDirectory.mkdirs())
          throw new RuntimeException("Could not store client key");

      Utils.writeBytesToFile(Utils.hexToByte(
        ticketJson.getString("sessionKey")), ClientCryptographicManager.buildSessionKeyPath()
      );
      Utils.writeBytesToFile(Utils.hexToByte(
        ticketJson.getString("sessionIv")), ClientCryptographicManager.buildSessionIVPath()
      );

      // Needham-Schroeder step 3
      AuthenticateResponse authenticateDatabaseResponse = databaseServiceStub.authenticate(
        AuthenticateRequest.newBuilder().setRequest(
          ByteString.copyFrom(
            Utils.serializeJson(
              Json.createObjectBuilder()
                .add("ticket", ticketJson.getString("targetTicket"))
                .add("timestampString", timestampString)
                .build()
      ))).build());

      // Needham-Schroeder steps 4 and 5 (altered to receive server cert)
      JsonObject authenticateJson = Utils.deserializeJson(crypto.decrypt(authenticateDatabaseResponse).getResponse().toByteArray());
      int challenge = Base.generateRandom(Integer.MAX_VALUE).intValue();
      CertificateFactory certGen = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certGen.generateCertificate(
        new ByteArrayInputStream(Utils.hexToByte(authenticateJson.getString("cert")))
      );
      cert.checkValidity();
      Utils.writeBytesToFile(
          cert.getPublicKey().getEncoded(), ClientCryptographicManager.buildSessionPublicKeyPath()
      );
      if (!crypto.check(authenticateDatabaseResponse))
        throw new RuntimeException("Authenticate response tampered");

      StillAliveResponse stillAliveResponse = databaseServiceStub.stillAlive(crypto.encrypt(StillAliveRequest.newBuilder().setRequest(
        ByteString.copyFrom(
          Utils.serializeJson(Json.createObjectBuilder()
            .add(
              "challenge", challenge
            ).add(
              "nonce", authenticateJson.getInt("nonce") - 1
            ).add(
              "publicKey", Utils.byteToHex(Utils.readBytesFromFile(ClientCryptographicManager.buildSelfPublicKeyPath()))
            ).build()
        ))).build()));

      if (!crypto.check(stillAliveResponse))
        throw new RuntimeException("Authenticate response tampered");
      JsonObject stillAliveJson = Utils.deserializeJson(crypto.decrypt(stillAliveResponse).getResponse().toByteArray());
      if(stillAliveJson.getInt("challenge") != challenge + 1)
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

      JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
      for (String username : usernames) {
        jsonArrayBuilder.add(username);
      }
      JsonArray usernamesJson = jsonArrayBuilder.build();

      jsonArrayBuilder = Json.createArrayBuilder();
      for (String password : passwords) {
        jsonArrayBuilder.add(crypto.encryptPassword(password));
      }
      JsonArray passwordsJson = jsonArrayBuilder.build();

      byte[] requestJson = Utils.serializeJson(Json.createObjectBuilder()
          .add("usernames", usernamesJson)
          .add("passwords", passwordsJson)
          .add("timestampString", timestampString)
          .build());

      if (debug)
        System.out.println("\tUserService: making rpc");

      CreateAccountResponse ignored = databaseServiceStub.createAccount(crypto.encrypt(
        CreateAccountRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

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
      byte[] requestJson = Utils.serializeJson(
          Utils.createJson(
              List.of("username", "password", "timestampString"),
              List.of(username, crypto.encryptPassword(password), timestampString)));

      if (debug)
        System.out.println("\tUserService: making rpc");
      DeleteAccountResponse ignored = databaseServiceStub.deleteAccount(crypto.encrypt(
        DeleteAccountRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

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
      byte[] requestJson = Utils.serializeJson(Utils.createJson(
        List.of("username", "password", "timestampString"),
        List.of(username, crypto.encryptPassword(password), timestampString)
      ));

      if (debug)
        System.out.println("\tUserService: making rpc");

      BalanceResponse balanceResponse = databaseServiceStub.balance(crypto.encrypt(
        BalanceRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

      if (!crypto.check(balanceResponse))
        throw new RuntimeException("Message contents were tampered with");

      if (debug)
        System.out.println("\tUserService: processing balance response");
      JsonObject responseJson = Utils.deserializeJson(crypto.decrypt(balanceResponse).getResponse().toByteArray());
      System.out.println(responseJson.getString("balance"));
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
      byte[] requestJson = Utils.serializeJson(Utils.createJson(
        List.of("username", "password", "timestampString"),
        List.of(username, crypto.encryptPassword(password), timestampString)
      ));

      if (debug)
        System.out.println("\tUserService: making rpc");

      GetMovementsResponse getAccountMovementsResponse = databaseServiceStub.getMovements(crypto.encrypt(
        GetMovementsRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

      if (!crypto.check(getAccountMovementsResponse))
        throw new RuntimeException("Message contents were tampered with");

      if (debug)
        System.out.println("\tUserService: processing get account movements response");
      JsonObject responseJson = Utils
          .deserializeJson(crypto.decrypt(getAccountMovementsResponse).getResponse().toByteArray());
      for (int i = 0; i < responseJson.getJsonArray("movements").size(); i++) {
        JsonObject movement = responseJson.getJsonArray("movements").getJsonObject(i);
        System.out.printf("Movement %d\n\tCurrency: %s\n\tDate: %s\n\tValue: %s\n\tDescription: %s\n", i + 1,
            movement.getString("currency"), movement.getString("date"), movement.getString("value"),
            movement.getString("description"));
      }
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void addExpense(String username, String password, String date, String amount, String description,
      String timestampString) {
    try {
      if (debug)
        System.out.println("\tUserService: encoding add expense request");
      byte[] requestJson = Utils.serializeJson(Utils.createJson(
        List.of("username", "password", "date", "amount", "description", "timestampString"),
        List.of(username, crypto.encryptPassword(password), date, amount, description, timestampString)
      ));

      if (debug)
        System.out.println("\tUserService: making rpc");
      AddExpenseResponse ignored = databaseServiceStub.addExpense(crypto.encrypt(
        AddExpenseRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

      if (debug)
        System.out.println("\tUserService: processing add expense response");
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
      byte[] requestJson = Utils.serializeJson(Utils.createJson(
        List.of("username", "password", "date", "amount", "description", "recipient", "timestampString"),
        List.of(username, crypto.encryptPassword(password), date, amount, description, recipient, timestampString)
      ));

      if (debug)
        System.out.println("\tUserService: making rpc");
      OrderPaymentResponse ignored = databaseServiceStub.orderPayment(crypto.encrypt(
        OrderPaymentRequest.newBuilder().setRequest(ByteString.copyFrom(requestJson)
      ).build()));

      if (debug)
        System.out.println("\tUserService: processing payment order response");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

}
