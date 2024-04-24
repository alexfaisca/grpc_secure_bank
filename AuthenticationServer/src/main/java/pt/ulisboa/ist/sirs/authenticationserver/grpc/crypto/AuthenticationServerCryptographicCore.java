package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;


public class AuthenticationServerCryptographicCore implements Base.CryptographicCore {

  public static byte[] decryptByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.decryptData(
      Base.readSecretKey(secretKeyPath),
      message,
      Base.readIv(ivPath)
    );
  }

  protected static byte[] encryptByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(secretKeyPath),
      message,
      Base.readIv(ivPath)
    );
  }
}
