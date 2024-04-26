package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.dto.KeyBundle;
import pt.ulisboa.ist.sirs.cryptology.AbstractAuthServerService;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.dto.DiffieHellmanParams;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CryptographicCore implements Base.CryptographicCore {
  protected static final String CLIENT_CACHE_DIR = "resources/crypto/";
  protected static final String SERVER_CACHE_DIR = "resources/crypto/server/";
  protected String getPublicKeyPath() {
    return Base.CryptographicCore.getPublicKeyPath();
  }
  protected String getPrivateKeyPath() {
    return Base.CryptographicCore.getPrivateKeyPath();
  }

  protected KeyBundle getKeyBundle(byte[] bundle, String privateKeyPath) throws Exception {
    byte[] decryptedBundle = Decrypter.decryptDataAsymmetric(Base.readPrivateKey(privateKeyPath), bundle);
    return new KeyBundle(
      Arrays.copyOfRange(decryptedBundle, 0, Base.SYMMETRIC_KEY_SIZE),
      Arrays.copyOfRange(decryptedBundle, Base.SYMMETRIC_KEY_SIZE, Base.SYMMETRIC_KEY_SIZE + Base.IV_SIZE)
    );
  }

  public byte[] bundleEKEParams(byte[] params, byte[] publicKeySpecs) {
    return Base.KeyManager.bundleParams(params, publicKeySpecs);
  }

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
    return Operations.decryptData(Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath));
  }

  protected static byte[] encryptUnsignedByteArray(
          byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Operations.encryptData(Base.readSecretKey(secretKeyPath), message, Base.readIv(ivPath));
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

  public DiffieHellmanExchangeParameters diffieHellmanExchange(
    byte[] clientPubEnc, String symmetricKeyPath, String ivPath
  ) throws Exception {
    DiffieHellmanParams params = AbstractAuthServerService.diffieHellmanExchange(
      symmetricKeyPath, ivPath, clientPubEnc
    );
    return new DiffieHellmanExchangeParameters(params.publicKey(), params.parameters());
  }
}