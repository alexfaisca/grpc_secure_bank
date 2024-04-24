package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;

import java.io.File;
import java.security.NoSuchAlgorithmException;

public class ClientCryptographicManager extends ClientCryptographicCore implements Base.KeyManager {
  private static final String publicKeyPath = "resources/crypto/client/publicKey";
  private static final String privateKeyPath = "resources/crypto/client/privateKey";

  public ClientCryptographicManager() {
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

  public static  String buildSelfPublicKeyPath() {
    return publicKeyPath;
  }

  public static String buildSelfPrivateKeyPath() {
    return privateKeyPath;
  }

  public byte[] encryptPassword(String password) throws NoSuchAlgorithmException {
    return Operations.hash(password.getBytes());
  }

  public byte[] encrypt(byte[] object) throws Exception {
    return encryptByteArray(object, buildSessionKeyPath(), buildSelfPrivateKeyPath(), buildSessionIVPath());
  }

  public boolean check(byte[] object) throws Exception {
    return !checkByteArray(object, buildSessionKeyPath(), buildSessionPublicKeyPath(), buildSessionIVPath());
  }

  public byte[] decrypt(byte[] object) throws Exception {
    return decryptByteArray(object, buildSessionKeyPath(), buildSessionIVPath());
  }
}
