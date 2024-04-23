package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.File;
import java.security.NoSuchAlgorithmException;

public class BankingClientCryptographicManager extends BankingClientCryptographicCore implements Base.KeyManager {

  public BankingClientCryptographicManager() {
    super();
  }

  public static void initializeCryptoCache() {
    File clientDirectory = new File("resources/crypto/client/");
    File sessionDirectory = new File("resources/crypto/session/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not initialize client dir");
    if (!sessionDirectory.exists())
      if (!sessionDirectory.mkdirs())
        throw new RuntimeException("Could not initialize session dir");
  }

  public static String buildSessionKeyPath() {
    return "resources/crypto/session/sessionKey";
  }

  public static String buildSessionIVPath() {
    return "resources/crypto/session/iv";
  }

  public static String buildSessionPublicKeyPath() {
    return "resources/crypto/session/publicKey";
  }

  public static String buildSelfPublicKeyPath() {
    return "resources/crypto/client/publicKey";
  }

  public static String buildSelfPrivateKeyPath() {
    return "resources/crypto/client/privateKey";
  }

  public String encryptPassword(String password) throws NoSuchAlgorithmException {
    return Utils.byteToHex(Operations.hash(password.getBytes()));
  }

  @SuppressWarnings(value = "all")
  public <P> P encrypt(P object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  @SuppressWarnings(value = "all")
  public <P> boolean check(P object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  @SuppressWarnings(value = "all")
  public <P> P decrypt(P object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public boolean check(AuthenticateResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public AuthenticateResponse decrypt(AuthenticateResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public boolean check(StillAliveResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public StillAliveResponse decrypt(StillAliveResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public StillAliveRequest encrypt(StillAliveRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public BalanceRequest encrypt(BalanceRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(BalanceResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public BalanceResponse decrypt(BalanceResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public CreateAccountRequest encrypt(CreateAccountRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(CreateAccountResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public CreateAccountResponse decrypt(CreateAccountResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public DeleteAccountRequest encrypt(DeleteAccountRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(DeleteAccountResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public DeleteAccountResponse decrypt(DeleteAccountResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public GetMovementsRequest encrypt(GetMovementsRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(GetMovementsResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public GetMovementsResponse decrypt(GetMovementsResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public AddExpenseRequest encrypt(AddExpenseRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(AddExpenseResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public AddExpenseResponse decrypt(AddExpenseResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public OrderPaymentRequest encrypt(OrderPaymentRequest object) throws Exception {
    return encrypt(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(OrderPaymentResponse object) throws Exception {
    return check(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public OrderPaymentResponse decrypt(OrderPaymentResponse object) throws Exception {
    return decrypt(object, buildSessionKeyPath(), buildSessionIVPath());
  }
}
