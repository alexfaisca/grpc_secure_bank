package pt.ulisboa.ist.sirs.databaseserver;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.contract.bankserver.BankServer;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc.DatabaseServiceImplBase;
import pt.ulisboa.ist.sirs.databaseserver.grpc.crypto.DatabaseServerCryptographicManager;
import pt.ulisboa.ist.sirs.databaseserver.repository.DatabaseManager;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.exceptions.ReplayAttackException;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import javax.json.*;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLOutput;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public final class DatabaseServerImpl extends DatabaseServiceImplBase {
  private final boolean debug;
  private final DatabaseManager databaseManager;
  private final DatabaseServerCryptographicManager crypto;
  private final List<OffsetDateTime> timestamps = new ArrayList<>();

  public DatabaseServerImpl(DatabaseManager databaseManager, DatabaseServerCryptographicManager crypto, boolean debug) {
    this.debug = debug;
    this.databaseManager = databaseManager;
    this.crypto = crypto;
  }

  public boolean isDebug() {
    return debug;
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

  @Override
  public void authenticate(AuthenticateRequest request, StreamObserver<AuthenticateResponse> responseObserver) {
    try {
      // Needham-Schroeder step 3
      JsonObject authenticateJson = Utils.deserializeJson(request.getRequest().toByteArray());

      String timestampString = authenticateJson.getString("timestampString");
      if (oldTimestampString(OffsetDateTime.parse(timestampString)))
        throw new ReplayAttackException();
      addTimestamp(OffsetDateTime.parse(timestampString));

      JsonObject ticketJson = Utils.deserializeJson(
        Operations.decryptData(
          Base.readSecretKey("resources/crypto/database/symmetricKey"),
          Utils.hexToByte(authenticateJson.getString("ticket")),
          Base.readIv("resources/crypto/database/iv")
      ));

      if (!ticketJson.getString("source").equals("user"))
        throw new TamperedMessageException();

      // Store session key and session iv
      crypto.createSession(Utils.hexToByte(ticketJson.getString("sessionKey")),  Utils.hexToByte(ticketJson.getString("sessionIv")));

      // Needham-Schroeder step 4
      crypto.setNonce((new Random()).nextInt());
      responseObserver.onNext(crypto.encrypt(AuthenticateResponse.newBuilder().setResponse(
        ByteString.copyFrom(
          Utils.serializeJson(
            Json.createObjectBuilder()
              .add("nonce", crypto.getNonce())
              .add("publicKey", Utils.byteToHex(Base.readPublicKey("resources/crypto/publicKey").getEncoded()))
              .build())
        )).build()));
      responseObserver.onCompleted();
    } catch (Exception e) {
      e.printStackTrace();
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void stillAlive(StillAliveRequest request, StreamObserver<StillAliveResponse> responseObserver) {
    try {
      // Needham-Schroeder step 5
      JsonObject stillAliveJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());

      if (!crypto.checkNonce(stillAliveJson.getInt("nonce") + 1))
        throw new TamperedMessageException();
      crypto.validateSession(Utils.hexToByte(stillAliveJson.getString("publicKey")));
      if (!crypto.check(request))
        throw new TamperedMessageException();

      responseObserver.onNext(crypto.encrypt(StillAliveResponse.newBuilder().setResponse(
        ByteString.copyFrom(
          Utils.serializeJson(
            Json.createObjectBuilder()
              .add("challenge", stillAliveJson.getInt("challenge") + 1)
              .build())
      )).build()));
      responseObserver.onCompleted();
    } catch (Exception e) {
      e.printStackTrace();
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  public void createAccount(CreateAccountRequest request, StreamObserver<CreateAccountResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: create account");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      List<String> usernames = new ArrayList<>();
      for (int i = 0; i < requestJson.getJsonArray("usernames").size(); i++)
        usernames.add(requestJson.getJsonArray("usernames").getString(i));
      byte[] password = crypto.decryptPassword(requestJson.getJsonArray("passwords").getString(0));
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf("\t\tUsername: %s\n\t\tPassword (Hex): %s\n", String.join(" ", usernames),
          Utils.byteToHex(password));

      databaseManager.createAccount(usernames, password, BigDecimal.ZERO, timestamp);

      responseObserver.onNext(crypto.encrypt(CreateAccountResponse.newBuilder().build()));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: create account successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  public void deleteAccount(DeleteAccountRequest request, StreamObserver<DeleteAccountResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: delete account");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String username = requestJson.getString("username");
      byte[] password = crypto.decryptPassword(requestJson.getString("password"));
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf("\t\tUsername: %s\n\t\tPassword (Hex): %s\n", username, Utils.byteToHex(password));

      databaseManager.deleteAccount(username, password, timestamp);

      responseObserver.onNext(crypto.encrypt(DeleteAccountResponse.newBuilder().build()));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: delete account successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void balance(BalanceRequest request, StreamObserver<BalanceResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: balance");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String username = requestJson.getString("username");
      byte[] password = crypto.decryptPassword(requestJson.getString("password"));
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf("\t\tUsername: %s\n\t\tPassword (Hex): %s\n", username, Utils.byteToHex(password));

      BigDecimal balance = databaseManager.balance(username, password, timestamp);

      responseObserver.onNext(crypto.encrypt(BalanceResponse.newBuilder().setResponse(
        ByteString.copyFrom(
          Utils.serializeJson(Utils.createJson(List.of("balance"), List.of(balance.toString())))))
        .build()
      ));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: balance successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  public void getMovements(GetMovementsRequest request, StreamObserver<GetMovementsResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: get account movements");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String username = requestJson.getString("username");
      byte[] password = crypto.decryptPassword(requestJson.getString("password"));
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf("\t\tUsername: %s\n\t\tPassword (Hex): %s\n", username, Utils.byteToHex(password));

      JsonArrayBuilder expenses = databaseManager.getMovements(username, password, timestamp);

      JsonObject responseJson = Json.createObjectBuilder().add("movements", expenses).build();

      responseObserver.onNext(crypto.encrypt(GetMovementsResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(responseJson))).build()
      ));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: get account movements successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Deprecated
  public void addExpense(AddExpenseRequest request, StreamObserver<AddExpenseResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: add expense");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String username = requestJson.getString("username");
      byte[] password = crypto.decryptPassword(requestJson.getString("password"));
      LocalDateTime date = LocalDateTime.parse(requestJson.getString("date"));
      BigDecimal amount = new BigDecimal(requestJson.getString("amount"));
      String description = requestJson.getString("description");
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf(
          "\t\tUsername: %s\n\t\tPassword (Hex): %s\n\t\tDate: %s\n\t\tAmount: %s\n\t\tDescription: %s\n", username,
          Utils.byteToHex(password), date, amount, description);

      // databaseManager.addExpense(username, password, date, amount, description,
      // timestamp);

      responseObserver.onNext(crypto.encrypt(AddExpenseResponse.newBuilder().build()));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: add expense successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  public void orderPayment(OrderPaymentRequest request, StreamObserver<OrderPaymentResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: order payment");

      if (!crypto.check(request))
        throw new TamperedMessageException();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String username = requestJson.getString("username");
      byte[] password = crypto.decryptPassword(requestJson.getString("password"));
      LocalDateTime date = LocalDateTime.parse(requestJson.getString("date"));
      BigDecimal amount = new BigDecimal(requestJson.getString("amount"));
      String description = requestJson.getString("description");
      String recipient = requestJson.getString("recipient");
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.printf(
          "\t\tUsername: %s\n\t\tPassword (Hex): %s\n\t\tRecipient: %s\n\t\tDate: %s\n\t\tAmount: %s\n\t\tDescription: %s\n",
          username, Utils.byteToHex(password), recipient, date, amount, description);

      databaseManager.orderPayment(username, password, date, amount, description, recipient, timestamp);

      responseObserver.onNext(crypto.encrypt(OrderPaymentResponse.newBuilder().build()));
      responseObserver.onCompleted();
      if (isDebug())
        System.out.println("\tDatabaseServerImpl: order payment successful");
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

}
