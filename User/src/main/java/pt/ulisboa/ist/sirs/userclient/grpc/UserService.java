package pt.ulisboa.ist.sirs.userclient.grpc;

import io.grpc.*;
import pt.ulisboa.ist.sirs.contract.bankserver.BankServer;
import pt.ulisboa.ist.sirs.contract.bankserver.BankingServiceGrpc;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;
import pt.ulisboa.ist.sirs.contract.bankserver.BankServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.BankingClientCryptographicManager;
import pt.ulisboa.ist.sirs.utils.Utils;
import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.*;
import java.security.*;
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
    private final String host;
    private final Integer port;
    private final BankingClientCryptographicManager crypto;
    private final ChannelCredentials credentials;
    private ManagedChannel bankChannel;
    private ManagedChannel authenticationServerChannel;
    String authenticationServerAddress;
    Integer authenticationServerPort;

    public UserServiceBuilder(
        String host,
        Integer port,
        String authenticationServerAddress,
        Integer authenticationServerPort,
        String ivPath,
        String secretKeyPath,
        String publicKeyPath,
        String privateKeyPath,
        String trustCertCollectionPath,
        boolean debug) throws Exception {
      this.debug = debug;
      this.host = host;
      this.port = port;
      this.authenticationServerAddress = authenticationServerAddress;
      this.authenticationServerPort = authenticationServerPort;
      this.crypto = new BankingClientCryptographicManager(
          ivPath,
          secretKeyPath,
          publicKeyPath,
          privateKeyPath);
      this.credentials = TlsChannelCredentials.newBuilder()
          .trustManager(new File(trustCertCollectionPath))
          .build();
    }

    public UserService build() {
      this.authenticationServerChannel = Grpc.newChannelBuilderForAddress(
          this.authenticationServerAddress,
          this.authenticationServerPort,
          this.credentials).build();

      this.bankChannel = Grpc.newChannelBuilderForAddress(
          this.host,
          this.port,
          this.credentials).build();

      return new UserService(this);
    }
  }

  private final boolean debug;
  private final BankingClientCryptographicManager crypto;
  private final AuthenticationServerServiceGrpc.AuthenticationServerServiceBlockingStub authenticationServerServiceStub;
  private final BankingServiceGrpc.BankingServiceBlockingStub bankingServiceStub;
  private final Logger logger;

  private UserService(UserServiceBuilder builder) {
    this.crypto = builder.crypto;
    this.debug = builder.debug;
    this.logger = Logger.getLogger("UserService");
    this.authenticationServerServiceStub = AuthenticationServerServiceGrpc
        .newBlockingStub(builder.authenticationServerChannel);
    this.bankingServiceStub = BankingServiceGrpc.newBlockingStub(builder.bankChannel);
    this.diffieHellman();
    this.authenticate(OffsetDateTime.now().toString());
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
              AuthenticationServer.DiffieHellmanExchangeRequest.newBuilder().setClientPublic(
                      ByteString.copyFrom(
                              keyPair.getPublic().getEncoded()
                      )).setTimestamp(OffsetDateTime.now().toString()
              ).build());

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
      Integer number =((temp[0] & 0xFF) << 24) |
              ((temp[1] & 0xFF) << 16) |
              ((temp[2] & 0xFF) << 8) |
              ((temp[3] & 0xFF));
      byte[] iv = Operations.generateIV(number, aesKey.getEncoded(), Utils.byteToHex(sharedSecret));
      Utils.writeBytesToFile(aesKey.getEncoded(), "resources/crypto/client/symmetricKey");
      Utils.writeBytesToFile(iv, "resources/crypto/client/iv");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

  public void authenticate(String timestampString) {
    try {
      // Needham-Schroeder step 1
      AuthenticationServer.AuthenticateResponse ticketResponse = authenticationServerServiceStub.authenticate(
          AuthenticationServer.AuthenticateRequest.newBuilder().setRequest(
              ByteString.copyFrom(
                  Utils.serializeJson(
                      Utils.createJson(
                          List.of("source", "target", "timestampString"),
                          List.of("user", "database", timestampString)))))
              .build());

      // Needham-Schroeder step 2
      JsonObject ticketJson = Utils.deserializeJson(
          Operations.decryptData(
              Base.readSecretKey("resources/crypto/client/symmetricKey"),
              ticketResponse.getResponse().toByteArray(),
              Base.readIv("resources/crypto/client/iv"))
      );

      if (!ticketJson.getString("target").equals("database")
          || !ticketJson.getString("timestampString").equals(timestampString))
        throw new TamperedMessageException();
      // Save session key and session iv
      Utils.writeBytesToFile(Utils.hexToByte(ticketJson.getString("sessionKey")),"resources/crypto/session/sessionKey");
      Utils.writeBytesToFile(Utils.hexToByte(ticketJson.getString("sessionIv")),"resources/crypto/session/iv");

      // Needham-Schroeder step 3
      BankServer.AuthenticateResponse authenticateDatabaseResponse = bankingServiceStub
          .authenticate(BankServer.AuthenticateRequest.newBuilder().setRequest(
              ByteString.copyFrom(
                  Utils.serializeJson(
                      Json.createObjectBuilder()
                          .add("ticket", ticketJson.getJsonString("targetTicket"))
                          .add("timestampString", timestampString)
                          .build())))
              .build());

      // Needham-Schroeder steps 4 and 5
      StillAliveResponse ignored = bankingServiceStub.stillAlive(crypto.encrypt(StillAliveRequest.newBuilder().setRequest(
        ByteString.copyFrom(
          Utils.serializeJson(Json.createObjectBuilder()
            .add(
              "nonce", Utils.deserializeJson(crypto.decrypt(authenticateDatabaseResponse).getResponse().toByteArray()).getInt("nonce") - 1
            ).add(
              "publicKey", Utils.byteToHex(Utils.readBytesFromFile("resources/crypto/publicKey"))
            ).build()
        ))).build()));
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

      CreateAccountResponse ignored = bankingServiceStub.createAccount(crypto.encrypt(
          CreateAccountRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

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
      DeleteAccountResponse ignored = bankingServiceStub.deleteAccount(crypto.encrypt(
          DeleteAccountRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

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
      byte[] requestJson = Utils.serializeJson(
          Utils.createJson(
              List.of("username", "password", "timestampString"),
              List.of(username, crypto.encryptPassword(password), timestampString)));

      if (debug)
        System.out.println("\tUserService: making rpc");

      BalanceResponse balanceResponse = bankingServiceStub.balance(crypto.encrypt(
          BalanceRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

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
      byte[] requestJson = Utils.serializeJson(
          Utils.createJson(
              List.of("username", "password", "timestampString"),
              List.of(username, crypto.encryptPassword(password), timestampString)));

      if (debug)
        System.out.println("\tUserService: making rpc");

      GetMovementsResponse getAccountMovementsResponse = bankingServiceStub.getMovements(crypto.encrypt(
          GetMovementsRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

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
      byte[] requestJson = Utils.serializeJson(
          Utils.createJson(
              List.of("username", "password", "date", "amount", "description", "timestampString"),
              List.of(username, crypto.encryptPassword(password), date, amount, description, timestampString)));

      if (debug)
        System.out.println("\tUserService: making rpc");
      AddExpenseResponse ignored = bankingServiceStub.addExpense(crypto.encrypt(
          AddExpenseRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

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
      byte[] requestJson = Utils.serializeJson(
          Utils.createJson(
              List.of("username", "password", "date", "amount", "description", "recipient", "timestampString"),
              List.of(username, crypto.encryptPassword(password), date, amount, description, recipient,
                  timestampString)));

      if (debug)
        System.out.println("\tUserService: making rpc");
      OrderPaymentResponse ignored = bankingServiceStub.orderPayment(crypto.encrypt(
          OrderPaymentRequest.newBuilder()
              .setRequest(
                  ByteString.copyFrom(requestJson))
              .build()));

      if (debug)
        System.out.println("\tUserService: processing payment order response");
    } catch (StatusRuntimeException e) {
      logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
    } catch (Exception e) {
      logger.log(Level.SEVERE, Arrays.toString(e.getStackTrace()), e);
    }
  }

}
