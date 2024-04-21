package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class DatabaseServerCryptographicManager extends DatabaseServerCryptographicCore implements Base.KeyManager {
  private final int MOCK_HASH = 0;
  private final DatabaseServerCryptographicInterceptor crypto;
  private final Map<String, Integer> nonces = new HashMap<>();

  public DatabaseServerCryptographicManager(
      DatabaseServerCryptographicInterceptor crypto,
      String publicKeyPath,
      String privateKeyPath) {
    super();
    addPublicKeyPath(MOCK_HASH, publicKeyPath);
    addPrivateKeyPath(MOCK_HASH, privateKeyPath);
    this.crypto = crypto;
  }

  private String buildSessionKeyPath(String client) {
    return "resources/crypto/session/" + client + "/sessionKey";
  }

  private String buildIVPath(String client) {
    return "resources/crypto/session/" + client + "/iv";
  }

  private String buildPublicKeyPath(String client) {
    return "resources/crypto/session/" + client + "/publicKey";
  }

  public void createSession(byte[] sessionKey, byte[] iv) {
    String client = crypto.getFromQueue(AuthenticateRequest.class);
    File clientDirectory = new File("resources/crypto/session/" + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
    Utils.writeBytesToFile(sessionKey, buildSessionKeyPath(client));
    Utils.writeBytesToFile(iv, buildIVPath(client));
  }

  public void setNonce(Integer nonce) {
    nonces.put(crypto.getFromQueue(AuthenticateRequest.class), nonce);
  }

  public Integer getNonce() {
    return nonces.get(crypto.getFromQueue(AuthenticateRequest.class));
  }

  public void validateSession(byte[] publicKey) throws Exception {
    String client = crypto.getFromQueue(StillAliveRequest.class);
    Utils.writeBytesToFile(publicKey, buildPublicKeyPath(client));
  }

  public boolean checkNonce(Integer nonce) {
    boolean result = false;
    if (nonces.containsKey(crypto.getFromQueue(StillAliveRequest.class))) {
      result = nonces.get(crypto.getFromQueue(StillAliveRequest.class)).equals(nonce);
      nonces.remove(crypto.getFromQueue(StillAliveRequest.class));
    }
    return result;
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

  public AuthenticateResponse encrypt(AuthenticateResponse object) throws Exception {
    String client = crypto.popFromQueue(AuthenticateRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public StillAliveResponse encrypt(StillAliveResponse object) throws Exception {
    String client = crypto.popFromQueue(StillAliveRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(StillAliveRequest object) throws Exception {
    String client = crypto.getFromQueue(StillAliveRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(StillAliveRequest.class);
      return false;
    }
    return true;
  }

  public StillAliveRequest decrypt(StillAliveRequest object) throws Exception {
    String client = crypto.getFromQueue(StillAliveRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public BalanceResponse encrypt(BalanceResponse object) throws Exception {
    String client = crypto.popFromQueue(BalanceRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(BalanceRequest object) throws Exception {
    String client = crypto.getFromQueue(BalanceRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public BalanceRequest decrypt(BalanceRequest object) throws Exception {
    String client = crypto.getFromQueue(BalanceRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public CreateAccountResponse encrypt(CreateAccountResponse object) throws Exception {
    String client = crypto.popFromQueue(CreateAccountRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(CreateAccountRequest object) throws Exception {
    String client = crypto.getFromQueue(CreateAccountRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public CreateAccountRequest decrypt(CreateAccountRequest object) throws Exception {
    String client = crypto.getFromQueue(CreateAccountRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public DeleteAccountResponse encrypt(DeleteAccountResponse object) throws Exception {
    String client = crypto.popFromQueue(DeleteAccountRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(DeleteAccountRequest object) throws Exception {
    String client = crypto.getFromQueue(DeleteAccountRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public DeleteAccountRequest decrypt(DeleteAccountRequest object) throws Exception {
    String client = crypto.getFromQueue(DeleteAccountRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public GetMovementsResponse encrypt(GetMovementsResponse object) throws Exception {
    String client = crypto.popFromQueue(GetMovementsRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(GetMovementsRequest object) throws Exception {
    String client = crypto.getFromQueue(GetMovementsRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public GetMovementsRequest decrypt(GetMovementsRequest object) throws Exception {
    String client = crypto.getFromQueue(GetMovementsRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public AddExpenseResponse encrypt(AddExpenseResponse object) throws Exception {
    String client = crypto.popFromQueue(AddExpenseRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(AddExpenseRequest object) throws Exception {
    String client = crypto.getFromQueue(AddExpenseRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public AddExpenseRequest decrypt(AddExpenseRequest object) throws Exception {
    String client = crypto.getFromQueue(AddExpenseRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }

  public OrderPaymentResponse encrypt(OrderPaymentResponse object) throws Exception {
    String client = crypto.popFromQueue(OrderPaymentRequest.class);
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(MOCK_HASH), buildIVPath(client));
  }

  public boolean check(OrderPaymentRequest object) throws Exception {
    String client = crypto.getFromQueue(OrderPaymentRequest.class);
    if (!check(object, buildSessionKeyPath(client), buildPublicKeyPath(client), buildIVPath(client))) {
      crypto.popFromQueue(BalanceRequest.class);
      return false;
    }
    return true;
  }

  public OrderPaymentRequest decrypt(OrderPaymentRequest object) throws Exception {
    String client = crypto.getFromQueue(OrderPaymentRequest.class);
    return decrypt(object, buildSessionKeyPath(client), buildIVPath(client));
  }
}
