package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CryptographicCore implements Base.CryptographicCore {
  protected static final String CLIENT_CACHE_DIR = "resources/crypto/";
  protected static final String SERVER_CACHE_DIR = "resources/crypto/server/";
  protected boolean checkByteArray(
          byte[] message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath), Base.readIv(ivPath)
    );
  }

  protected static byte[] decryptByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.decryptByteArray(message, Base.readSecretKey(secretKeyPath), Base.readIv(ivPath));
  }

  protected static byte[] encryptByteArray(
          byte[] message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return Encrypter.encryptByteArray(
      message, Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    );
  }

  protected static byte[] decryptUnsignedByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.decryptData(
      Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath)
    );
  }

  protected static byte[] encryptUnsignedByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath)
    );
  }

  protected byte[] decryptWithEphemeral(
          byte[] ephemeralKey, byte[] cipher, byte[] ephemeralIV
  ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
          NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    return Decrypter.decryptWithEphemeral(ephemeralKey, cipher, ephemeralIV);
  }

  protected byte[] encryptWithEphemeral(
          byte[] ephemeralKey, byte[] message, byte[] ephemeralIV
  ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
          NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    return Encrypter.encryptWithEphemeral(ephemeralKey, message, ephemeralIV);
  }
}