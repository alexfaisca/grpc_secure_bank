package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;

import java.security.NoSuchAlgorithmException;

public abstract class ClientCryptographicCore implements Base.CryptographicCore {
  protected static final String CLIENT_DIR = "resources/crypto/client/";
  protected static final String AUTH_DIR = "resources/crypto/client/";
  protected static final String SESSION_DIR = "resources/crypto/session/";
  protected static boolean checkByteArray(
    byte[] message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath), Base.readIv(ivPath)
    );
  }

  protected static byte[] decryptByteArray(byte[] message, String secretKeyPath, String ivPath) throws Exception {
    return Decrypter.decryptByteArray(message, Base.readSecretKey(secretKeyPath), Base.readIv(ivPath));
  }

  protected static byte[] encryptByteArray(
    byte[] message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return Encrypter.encryptByteArray(
      message, Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    );
  }

  protected static byte[] decryptByteArrayUnsigned(
    byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.decryptData(
      Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath)
    );
  }

  protected static byte[] encryptByteArrayUnsigned(
    byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath)
    );
  }

  protected static byte[] hash(byte[] message) {
    try {
      return Operations.hash(message);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e.getMessage());
    }
  }
}
