package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.exceptions.CannotInitializeClientCache;
import pt.ulisboa.ist.sirs.cryptology.AbstractAuthServerService;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.dto.DiffieHellmanParams;

import java.io.File;

public class AuthenticationServerCryptographicManager extends CryptographicCore implements Base.KeyManager {
  private final ServerCryptographicInterceptor crypto;

  public AuthenticationServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  // For now database symmetricKey and iv are distributed prior to application initialization, hence are static files
  public String getTargetServerSymmetricKeyPath(String server) {
      return SERVER_CACHE_DIR + server + "/symmetricKey";
  }

  public String getTargetServerIVPath(String server) {
      return SERVER_CACHE_DIR + server + "/iv";
  }

  public String buildSymmetricKeyPath(String client) {
    return CLIENT_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
    return CLIENT_CACHE_DIR + client + "/iv";
  }

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  public void initializeClientCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new CannotInitializeClientCache(client);
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptUnsignedByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptUnsignedByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] bundleTicket(String source, byte[] sessionKey, byte[] sessionIV, String target) throws Exception {
    return Operations.encryptData(
      Base.readSecretKey(getTargetServerSymmetricKeyPath(target)),
      Base.KeyManager.bundleTicket(source, sessionKey, sessionIV),
      Base.readIv(getTargetServerIVPath(target))
    );
  }

  public synchronized DiffieHellmanExchangeParameters diffieHellmanExchange(byte[] clientPubEnc, String client) throws Exception {
    initializeClientCache(client);
    DiffieHellmanParams params = AbstractAuthServerService.diffieHellmanExchange(
      buildSymmetricKeyPath(client),
      buildIVPath(client),
      clientPubEnc
    );
    return new DiffieHellmanExchangeParameters(params.publicKey(), params.parameters());
  }
}
