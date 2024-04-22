package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.Utils;

public class DatabaseServerCryptographicCore implements Base.CryptographicCore {

  protected static <ReqT> boolean check(ReqT ignore1,
      String ignore2, String ignore3, String ignore4)
      throws Exception {
    throw new Exception("No such request");
  }

  protected static <ReqT> ReqT decrypt(ReqT ignore1,
      String ignore2, String ignore3)
      throws Exception {
    throw new Exception("No such request");
  }

  protected static <RespT> RespT encrypt(RespT ignore1,
      String ignore2, String ignore3, String ignore4) throws Exception {
    throw new Exception("No such response");
  }

  protected static boolean check(StillAliveRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath)
      throws Exception {
    return Decrypter.check(
        message.getRequest().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(BalanceRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath)
      throws Exception {
    return Decrypter.check(
        message.getRequest().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(CreateAccountRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getRequest().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(DeleteAccountRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getRequest().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(GetMovementsRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getRequest().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }
  @SuppressWarnings(value = "all")
  @Deprecated
  protected static boolean check(AddExpenseRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return true;
  }
  @SuppressWarnings(value = "all")
  @Deprecated
  protected static boolean check(OrderPaymentRequest message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return true;
  }

  protected static StillAliveRequest decrypt(StillAliveRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return StillAliveRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static BalanceRequest decrypt(BalanceRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return BalanceRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static CreateAccountRequest decrypt(CreateAccountRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return CreateAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static DeleteAccountRequest decrypt(DeleteAccountRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return DeleteAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static GetMovementsRequest decrypt(GetMovementsRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return GetMovementsRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static AddExpenseRequest decrypt(AddExpenseRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return AddExpenseRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static OrderPaymentRequest decrypt(OrderPaymentRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return OrderPaymentRequest.newBuilder().setRequest(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static DatabaseServer.AuthenticateRequest decrypt(DatabaseServer.AuthenticateRequest message,
      String secretKeyPath, String ivPath) throws Exception {
    return DatabaseServer.AuthenticateRequest.newBuilder().setRequest(
      ByteString.copyFrom(Operations.decryptData(
        Base.readSecretKey(secretKeyPath),
        message.getRequest().toByteArray(),
        Base.readIv(ivPath)
      ))).build();
  }

  protected static DatabaseServer.AuthenticateResponse encrypt(DatabaseServer.AuthenticateResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return DatabaseServer.AuthenticateResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static StillAliveResponse encrypt(StillAliveResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return StillAliveResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static BalanceResponse encrypt(BalanceResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return BalanceResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static CreateAccountResponse encrypt(CreateAccountResponse message,
      String secretKey, String privateKeyPath, String ivPath) throws Exception {
    return CreateAccountResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKey),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static DeleteAccountResponse encrypt(DeleteAccountResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return DeleteAccountResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static GetMovementsResponse encrypt(GetMovementsResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return GetMovementsResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static AddExpenseResponse encrypt(AddExpenseResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return AddExpenseResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static OrderPaymentResponse encrypt(OrderPaymentResponse message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return OrderPaymentResponse.newBuilder().setResponse(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }
}
