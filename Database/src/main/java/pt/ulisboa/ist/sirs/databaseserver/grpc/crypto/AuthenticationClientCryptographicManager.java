package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.databaseserver.dto.KeyParamsDto;
import pt.ulisboa.ist.sirs.dto.EKEParams;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

  public KeyParamsDto unbundleKeyParams(SecretKey secretKey, byte[] bundle, byte[] ephemeralIV) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    EKEParams params = Base.KeyManager.unbundleParams(Operations.decryptData(
      secretKey,
      bundle,
      ephemeralIV
    ));
    return new KeyParamsDto(params.params(), params.publicKeySpecs());
  }

  public void validateServer(byte[] clientCert) throws CertificateException {
    CertificateFactory certGen = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certGen.generateCertificate(
      new ByteArrayInputStream(clientCert)
    );
    cert.checkValidity();
    Utils.writeBytesToFile(cert.getPublicKey().getEncoded(), buildPublicKeyPath());
  }

  public void initializeSession(byte[] secretKey, byte[] iv) {
    Utils.writeBytesToFile(secretKey, buildSessionKeyPath());
    Utils.writeBytesToFile(iv, buildSessionIVPath());
  }
}
