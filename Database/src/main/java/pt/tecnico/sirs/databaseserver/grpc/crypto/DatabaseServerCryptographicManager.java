package pt.tecnico.sirs.databaseserver.grpc.crypto;

import pt.tecnico.sirs.contract.databaseserver.DatabaseServer.*;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

public class DatabaseServerCryptographicManager extends DatabaseServerCryptographicCore implements Base.KeyManager {
  private final int MOCK_HASH = 0;

  public DatabaseServerCryptographicManager(
      String ivPath,
      String secretKeyPath,
      String publicKeyPath,
      String privateKeyPath) {
    super();
    this.addIvPath(MOCK_HASH, ivPath);
    this.addSecretKeyPath(MOCK_HASH, secretKeyPath);
    this.addPublicKeyPath(MOCK_HASH, publicKeyPath);
    this.addPrivateKeyPath(MOCK_HASH, privateKeyPath);
  }

  public byte[] decryptPassword(String password) {
    return Utils.hexToByte(password);
  }

  public <P> P encrypt(P object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public <P> boolean check(P object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public <P> P decrypt(P object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public BalanceResponse encrypt(BalanceResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(BalanceRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public BalanceRequest decrypt(BalanceRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public CreateAccountResponse encrypt(CreateAccountResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(CreateAccountRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public CreateAccountRequest decrypt(CreateAccountRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public DeleteAccountResponse encrypt(DeleteAccountResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(DeleteAccountRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public DeleteAccountRequest decrypt(DeleteAccountRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public GetMovementsResponse encrypt(GetMovementsResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(GetMovementsRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public GetMovementsRequest decrypt(GetMovementsRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public AddExpenseResponse encrypt(AddExpenseResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(AddExpenseRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public AddExpenseRequest decrypt(AddExpenseRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public OrderPaymentResponse encrypt(OrderPaymentResponse object) throws Exception {
    return encrypt(object, getSecretKeyPath(MOCK_HASH), getPrivateKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public boolean check(OrderPaymentRequest object) throws Exception {
    return check(object, getSecretKeyPath(MOCK_HASH), getPublicKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }

  public OrderPaymentRequest decrypt(OrderPaymentRequest object) throws Exception {
    return decrypt(object, getSecretKeyPath(MOCK_HASH), getIvPath(MOCK_HASH));
  }
}
