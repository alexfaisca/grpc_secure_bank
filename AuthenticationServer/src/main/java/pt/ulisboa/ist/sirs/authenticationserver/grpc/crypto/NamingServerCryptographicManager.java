package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class NamingServerCryptographicManager extends NamingServerCryptographicCore {
  private final ServerCryptographicInterceptor crypto;
  private final Map<String, Integer> nonces = new HashMap<>();
  private static final String CLIENT_CACHE_DIR = "resources/crypto/server/";

  public NamingServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  public String getPublicKeyPath() {
      return Base.CryptographicCore.getPublicKeyPath();
  }

  public String getPrivateKeyPath() {
      return Base.CryptographicCore.getPrivateKeyPath();
  }

  public void initializeClientCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
  }

  public boolean checkServerCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    return clientDirectory.exists();
  }

  public String buildSymmetricKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
      return CLIENT_CACHE_DIR + client + "/iv";
  }

  public String buildPublicKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/publicKey";
  }

  public <Req> String getClientHash(Req request) {
    return crypto.getClientHash(request);
  }

  public void setNonce(Integer nonce) {
      nonces.put(crypto.getFromQueue(EncryptedKeyExchangeRequest.class), nonce);
  }

  public Integer getNonce() {
      return nonces.get(crypto.getFromQueue(EncryptedKeyExchangeChallengeRequest.class));
  }

  public boolean checkNonce(Integer nonce) {
    boolean result = false;
    if (nonces.containsKey(crypto.getFromQueue(EncryptedKeyExchangeChallengeRequest.class))) {
      result = nonces.get(crypto.getFromQueue(EncryptedKeyExchangeChallengeRequest.class)).equals(nonce);
      nonces.remove(crypto.getFromQueue(EncryptedKeyExchangeChallengeRequest.class));
    }
    return result;
  }

  public <P> P encrypt(P object) throws Exception {
    return encrypt(object, "", "");
  }

  public <P> P decrypt(P object) throws Exception {
    return decrypt(object, "", "");
  }

  public RegisterResponse encrypt(RegisterResponse object) throws Exception {
    String client = crypto.getFromQueue(RegisterRequest.class);
    return object;
  }

  public RegisterRequest decrypt(RegisterRequest object) throws Exception {
    String client = crypto.getFromQueue(RegisterRequest.class);
    return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public LookupResponse encrypt(LookupResponse object) throws Exception {
    String client = crypto.getFromQueue(LookupRequest.class);
    return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public LookupRequest decrypt(LookupRequest object) throws Exception {
    String client = crypto.getFromQueue(LookupRequest.class);
    return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public DeleteResponse encrypt(DeleteResponse object) throws Exception {
    String client = crypto.getFromQueue(DeleteRequest.class);
    return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public DeleteRequest decrypt(DeleteRequest object) throws Exception {
    String client = crypto.getFromQueue(DeleteRequest.class);
    return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }
}
