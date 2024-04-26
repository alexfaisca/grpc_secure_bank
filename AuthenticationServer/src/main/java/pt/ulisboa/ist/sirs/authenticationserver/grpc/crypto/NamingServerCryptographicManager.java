package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.dto.KeyBundle;
import pt.ulisboa.ist.sirs.authenticationserver.exceptions.CannotInitializeClientCache;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.AbstractAuthServerService;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.dto.DiffieHellmanParams;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class NamingServerCryptographicManager extends CryptographicCore {
  private final ServerCryptographicInterceptor crypto;
  private final Map<String, Long> nonces = new HashMap<>();

  public NamingServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  @SuppressWarnings("all")
  public String getPublicKeyPath() {
      return Base.CryptographicCore.getPublicKeyPath();
  }

  public String getPrivateKeyPath() {
      return Base.CryptographicCore.getPrivateKeyPath();
  }

  public String buildSymmetricKeyPath(String client) {
      return SERVER_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
      return SERVER_CACHE_DIR + client + "/iv";
  }

  public String buildPublicKeyPath(String client) {
      return SERVER_CACHE_DIR + client + "/publicKey";
  }

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  public boolean checkServerCache(String client) {
    File clientDirectory = new File(SERVER_CACHE_DIR + client + "/");
    return !clientDirectory.exists();
  }

  public long initializeNonce() {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    long random = (new Random()).nextLong();
    nonces.put(client, random);
    return random;
  }

  public boolean checkNonce(Long nonce) {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName());
    boolean result = false;
    if (nonces.containsKey(client)) {
      result = nonces.get(client).equals(nonce);
      nonces.remove(client);
    }
    return result;
  }

  private void initializeClientDir(String client) {
    File clientDirectory = new File(SERVER_CACHE_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new CannotInitializeClientCache(client);
  }

  public void validateSession(byte[] clientCert) throws CertificateException {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    CertificateFactory certGen = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) certGen.generateCertificate(
            new ByteArrayInputStream(clientCert)
    );
    cert.checkValidity();
    initializeClientDir(client);
    Utils.writeBytesToFile(cert.getPublicKey().getEncoded(), buildPublicKeyPath(client));
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSymmetricKeyPath(client), getPrivateKeyPath(), buildIVPath(client));
  }

  public boolean checkByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return !checkByteArray(object, buildSymmetricKeyPath(client), buildPublicKeyPath(client), buildIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public KeyBundle getEphemeralBundle(byte[] bundle) throws Exception {
    byte[] decryptedBundle = Operations.decryptDataAsymmetric(
      Base.readPrivateKey(getPrivateKeyPath()),
      bundle
    );
    return new KeyBundle(
      Arrays.copyOfRange(decryptedBundle, 0, Base.SYMMETRIC_KEY_SIZE),
      Arrays.copyOfRange(decryptedBundle, Base.SYMMETRIC_KEY_SIZE, Base.SYMMETRIC_KEY_SIZE + Base.IV_SIZE)
    );
  }

  public byte[] encryptWithSession(byte[] message, String client) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(buildSymmetricKeyPath(client)),
      message,
      Base.readIv(buildIVPath(client))
    );
  }

  public byte[] encryptWithEphemeral(
    KeyBundle bundle, byte[] message
  ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
          NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    return super.encryptWithEphemeral(bundle.ephemeralKey(), message, bundle.ephemeralIV());
  }

  public byte[] decryptWithEphemeral(
    KeyBundle bundle, byte[] cipher
  ) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
          NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    return super.decryptWithEphemeral(bundle.ephemeralKey(), cipher, bundle.ephemeralIV());
  }

  public byte[] bundleEKEParams(byte[] params, byte[] publicKeySpecs) {
    return Base.KeyManager.unbundleParams(params, publicKeySpecs);
  }

  public DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] clientPubEnc, String client) throws Exception {
    initializeClientDir(client);
    DiffieHellmanParams params = AbstractAuthServerService.diffieHellmanExchange(
      buildSymmetricKeyPath(client),
      buildIVPath(client),
      clientPubEnc
    );
    return new DiffieHellmanExchangeParameters(params.publicKey(), params.parameters());
  }
}
