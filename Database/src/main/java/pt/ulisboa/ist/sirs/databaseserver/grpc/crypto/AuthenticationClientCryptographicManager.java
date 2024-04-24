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

  public byte[] encryptByteArray(byte[] object) throws Exception {
    return encryptByteArray(object, buildSessionKeyPath(), getPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean checkByteArray(byte[] object) throws Exception {
    return !checkByteArray(object, buildSessionKeyPath(), buildPublicKeyPath(), buildSessionIVPath());
  }

  public byte[] decryptByteArray(byte[] object) throws Exception {
    return decryptByteArray(object, buildSessionKeyPath(), buildSessionIVPath());
  }

  public String getPrivateKeyPath() {
    return "resources/crypto/self/privateKey";
  }

  public String buildPublicKeyPath() {
    return "resources/crypto/auth/publicKey";
  }

  public String buildSessionKeyPath() {
    return "resources/crypto/auth/symmetricKey";
  }

  public String buildSessionIVPath() {
    return "resources/crypto/auth/iv";
  }

}
