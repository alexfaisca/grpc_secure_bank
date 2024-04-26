package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.databaseserver.dto.TicketDto;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class DatabaseServerCryptographicManager extends CryptographicCore {
  private final String publicKeyPath;
  private final String privateKeyPath;
  private final DatabaseServerCryptographicInterceptor crypto;
  private final Map<String, Long> nonces = new HashMap<>();

  public DatabaseServerCryptographicManager(
      DatabaseServerCryptographicInterceptor crypto,
      String publicKeyPath,
      String privateKeyPath) {
    super();
    this.publicKeyPath = publicKeyPath;
    this.privateKeyPath = privateKeyPath;
    this.crypto = crypto;
  }

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  @SuppressWarnings("all")
  public String getPublicKeyPath() {
    return this.publicKeyPath;
  }

  public String getPrivateKeyPath() {
    return this.privateKeyPath;
  }

  public String buildAuthKeyPath() {
    return AUTH_DIR + "symmetricKey";
  }

  public String buildAuthIVPath() {
    return AUTH_DIR + "iv";
  }

  private String buildSessionKeyPath(String client) {
    return SESSION_DIR + client + "/sessionKey";
  }

  private String buildSessionIVPath(String client) {
    return SESSION_DIR + client + "/iv";
  }

  private String buildSessionPublicKeyPath(String client) {
    return SESSION_DIR + client + "/publicKey";
  }

  public void createSession(byte[] sessionKey, byte[] iv) {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName());
    File clientDirectory = new File(SESSION_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
    Utils.writeBytesToFile(sessionKey, buildSessionKeyPath(client));
    Utils.writeBytesToFile(iv, buildSessionIVPath(client));
  }

  public long initializeNonce() {
    long nonce = (new Random()).nextLong();
    nonces.put(crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName()), nonce);
    return nonce;
  }

  public boolean checkNonce(Long nonce) {
    boolean result = false;
    if (nonces.containsKey(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName()))) {
      result = nonces.get(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName())).equals(nonce);
      nonces.remove(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName()));
    }
    return result;
  }

  public void validateSession(byte[] publicKey) {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName());
    Utils.writeBytesToFile(publicKey, buildSessionPublicKeyPath(client));
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSessionKeyPath(client), getPrivateKeyPath(), buildSessionIVPath(client));
  }

  public boolean checkByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return !checkByteArray(object, buildSessionKeyPath(client), buildSessionPublicKeyPath(client), buildSessionIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSessionKeyPath(client), buildSessionIVPath(client));
  }

  public TicketDto unbundleTicket(byte[] ticket) throws Exception {
    return unbundleTicket(ticket, buildAuthKeyPath(), buildAuthIVPath());
  }
}
