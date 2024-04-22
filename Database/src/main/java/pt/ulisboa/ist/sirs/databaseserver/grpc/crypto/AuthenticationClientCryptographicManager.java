package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import java.io.File;

public class AuthenticationClientCryptographicManager extends AuthenticationClientCryptographicCore {
  public AuthenticationClientCryptographicManager() {
    super();
  }

  public String getAuthCacheDir() {
    return "resources/crypto/auth";
  }

  public void initializeAuthCache() {
    File clientDirectory = new File(this.getAuthCacheDir());
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
  }

  public String buildSessionKeyPath() {
    return "resources/crypto/auth/symmetricKey";
  }

  public String buildIVPath() {
    return "resources/crypto/auth/iv";
  }

  public String buildPublicKeyPath() {
    return "resources/crypto/auth/publicKey";
  }

}
