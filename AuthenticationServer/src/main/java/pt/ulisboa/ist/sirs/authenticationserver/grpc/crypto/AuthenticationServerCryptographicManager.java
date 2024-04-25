package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;

import java.io.File;

public class AuthenticationServerCryptographicManager extends AuthenticationServerCryptographicCore implements Base.KeyManager {
  private final ServerCryptographicInterceptor crypto;
  private static final String CLIENT_CACHE_DIR = "resources/crypto/";

  public AuthenticationServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  // For now database symmetricKey and iv are distributed prior to application initialization, hence are static files
  public String getTargetServerSymmetricKeyPath(String server) {
      return "resources/crypto/server/" + server + "/symmetricKey";
  }

  public String getTargetServerIVPath(String server) {
      return "resources/crypto/server/" + server + "/iv";
  }

  public void initializeClientCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
  }

  public String buildSymmetricKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
      return CLIENT_CACHE_DIR + client + "/iv";
  }

  public String getClientHash(String methodName) {
      return crypto.getClientHash(methodName);
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] bundleTicket(String source, byte[] sessionKey, byte[] sessionIV, String target) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(getTargetServerSymmetricKeyPath(target)),
      Base.KeyManager.bundleTicket(source, sessionKey, sessionIV),
      Base.readIv(getTargetServerIVPath(target))
    );
  }
}
