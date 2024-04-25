package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class NamingServerCryptographicManager extends NamingServerCryptographicCore {
  private final ServerCryptographicInterceptor crypto;
  private final Map<String, Long> nonces = new HashMap<>();
  private static final String CLIENT_CACHE_DIR = "resources/crypto/server/";

  public NamingServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  @SuppressWarnings("all")
  public String getPublicKeyPath() {
      return Base.CryptographicCore.getPublicKeyPath();
  }

  public String getPrivateKeyPath() {
      return Base.CryptographicCore.getPrivateKeyPath();
  }

  public boolean checkServerCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    return !clientDirectory.exists();
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

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  public long initializeNonce() {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    long random = (new Random()).nextLong();
    nonces.put(client, random);
    return random;
  }

  public boolean checkNonce(Long nonce) {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName());
    boolean result = false;
    if (nonces.containsKey(client)) {
      result = nonces.get(client).equals(nonce);
      nonces.remove(client);
    }
    return result;
  }

  public void validateSession(byte[] clientPublicKey) {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    File clientDirectory = new File("resources/crypto/server/" + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
    Utils.writeBytesToFile(clientPublicKey, buildPublicKeyPath(client));
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSymmetricKeyPath(client), getPrivateKeyPath(), buildIVPath(client));
  }

  public boolean checkByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return !checkByteArray(object, buildSymmetricKeyPath(client), buildPublicKeyPath(client), buildIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] bundleEKEParams(byte[] params, byte[] publicKeySpecs) {
    return Base.KeyManager.unbundleParams(params, publicKeySpecs);
  }
}
