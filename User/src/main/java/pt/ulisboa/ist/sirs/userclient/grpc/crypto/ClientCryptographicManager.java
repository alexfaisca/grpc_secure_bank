package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientCryptographicManager extends ClientCryptographicCore implements Base.KeyManager, Base.AuthClient {
  public ClientCryptographicManager() {
    super();
  }

  public static void initializeCryptoCache() {
    File clientDirectory = new File(CLIENT_DIR);
    File sessionDirectory = new File(SESSION_DIR);
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not initialize client dir");
    if (!sessionDirectory.exists())
      if (!sessionDirectory.mkdirs())
        throw new RuntimeException("Could not initialize session dir");
  }

  public static String buildSessionKeyPath() {
    return SESSION_DIR + "sessionKey";
  }

  public static String buildSessionIVPath() {
    return SESSION_DIR + "iv";
  }

  public static String buildAuthKeyPath() {
    return AUTH_DIR + "symmetricKey";
  }

  public static String buildAuthIVPath() {
    return AUTH_DIR + "iv";
  }

  public static String buildSessionPublicKeyPath() {
    return SESSION_DIR + "publicKey";
  }

  public static  String buildSelfPublicKeyPath() {
    return CLIENT_DIR + "publicKey";
  }

  public static String buildSelfPrivateKeyPath() {
    return CLIENT_DIR + "privateKey";
  }

  public void validateSession(byte[] clientCert) throws CertificateException {
    CertificateFactory certGen = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certGen.generateCertificate(
            new ByteArrayInputStream(clientCert)
    );
    cert.checkValidity();
    Utils.writeBytesToFile(cert.getPublicKey().getEncoded(), buildSessionPublicKeyPath());
  }

  public void initializeSession(byte[] sessionKey, byte[] sessionIV) {
    Utils.writeBytesToFile(sessionKey, ClientCryptographicManager.buildSessionKeyPath());
    Utils.writeBytesToFile(sessionIV, ClientCryptographicManager.buildSessionIVPath());
  }

  public void initializeAuth(byte[] secretKey, byte[] iv) {
    Utils.writeBytesToFile(secretKey, ClientCryptographicManager.buildAuthKeyPath());
    Utils.writeBytesToFile(iv, ClientCryptographicManager.buildAuthIVPath());
  }

  public byte[] encryptPassword(String password) {
    return hash(password.getBytes());
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

  public byte[] decryptAuth(byte[] object) throws Exception {
    return decryptByteArrayUnsigned(object, buildAuthKeyPath(), buildAuthIVPath());
  }

  public byte[] encryptAuth(byte[] object) throws Exception {
    return encryptByteArrayUnsigned(object, buildAuthKeyPath(), buildAuthIVPath());
  }
}
