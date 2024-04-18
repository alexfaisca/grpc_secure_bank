package pt.tecnico.sirs.userclient.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.tecnico.sirs.contract.bankserver.BankServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Base.CryptographicCore.Decrypter;
import pt.ulisboa.ist.sirs.cryptology.Base.CryptographicCore.Encrypter;
import pt.ulisboa.ist.sirs.utils.*;

public abstract class BankingClientCryptographicCore implements Base.CryptographicCore {

  protected static <RespT> boolean check(RespT ignore1,
      RespT ignore2, String ignore3, String ignore4)
      throws Exception {
    throw new Exception("No such request");
  }

  protected static <RespT> RespT decrypt(RespT ignore1,
      String ignore2, String ignore3)
      throws Exception {
    throw new Exception("No such request");
  }

  protected static <ReqT> ReqT encrypt(ReqT ignore1,
      String ignore2, String ignore3, String ignore4) throws Exception {
    throw new Exception("No such response");
  }

  protected static boolean check(BalanceResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath)
      throws Exception {
    return Decrypter.check(
        message.getResponse().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(CreateAccountResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getResponse().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(DeleteAccountResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getResponse().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(GetMovementsResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return Decrypter.check(
        message.getResponse().toByteArray(),
        Base.readSecretKey(secretKeyPath),
        Base.readPublicKey(publicKeyPath),
        Base.readIv(ivPath));
  }

  protected static boolean check(AddExpenseResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return true;
  }

  protected static boolean check(OrderPaymentResponse message,
      String secretKeyPath, String publicKeyPath, String ivPath) throws Exception {
    return true;
  }

  protected static BalanceResponse decrypt(BalanceResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return BalanceResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static CreateAccountResponse decrypt(CreateAccountResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return CreateAccountResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static DeleteAccountResponse decrypt(DeleteAccountResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return DeleteAccountResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static GetMovementsResponse decrypt(GetMovementsResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return GetMovementsResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static AddExpenseResponse decrypt(AddExpenseResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return AddExpenseResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static OrderPaymentResponse decrypt(OrderPaymentResponse message,
      String secretKeyPath, String ivPath) throws Exception {
    return OrderPaymentResponse.newBuilder().setResponse(
        ByteString.copyFrom(Utils.serializeJson(
            Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readIv(ivPath)))))
        .build();
  }

  protected static BalanceRequest encrypt(BalanceRequest message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return BalanceRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static CreateAccountRequest encrypt(CreateAccountRequest message,
      String secretKey, String privateKeyPath, String ivPath) throws Exception {
    return CreateAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKey),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static DeleteAccountRequest encrypt(DeleteAccountRequest message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return DeleteAccountRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static GetMovementsRequest encrypt(GetMovementsRequest message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return GetMovementsRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static AddExpenseRequest encrypt(AddExpenseRequest message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return AddExpenseRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }

  protected static OrderPaymentRequest encrypt(OrderPaymentRequest message,
      String secretKeyPath, String privateKeyPath, String ivPath) throws Exception {
    return OrderPaymentRequest.newBuilder().setRequest(
        ByteString.copyFrom(
            Encrypter.encrypt(message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath),
                Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath))))
        .build();
  }
}
