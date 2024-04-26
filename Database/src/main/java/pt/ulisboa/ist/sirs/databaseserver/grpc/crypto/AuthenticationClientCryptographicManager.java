package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class AuthenticationClientCryptographicManager extends AuthenticationClientCryptographicCore implements Base.EKEClientManager {
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
