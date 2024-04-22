package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;

import java.io.File;

public class AuthenticationServerCryptographicManager extends AuthenticationServerCryptographicCore {
  private final ServerCryptographicInterceptor crypto;
  private static final String CLIENT_CACHE_DIR = "resources/crypto/";

  public AuthenticationServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  // For now database symmetricKey and iv are distributed prior to application initialization, hence are static files
  public String getTargetServerSymmetricKeyPath(String server) {
      return "resources/crypto/server/" + server + "/symmetricKey";
  }

  public String getTargetServerIVPath(String server) {
      return "resources/crypto/server/" + server + "/iv";
  }

  public void initializeClientCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
  }

  public String buildSymmetricKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
      return CLIENT_CACHE_DIR + client + "/iv";
  }

  public <Req> String getClientHash(Req request) {
      return crypto.getClientHash(request);
  }

  public <P> P encrypt(P object) throws Exception {
    return encrypt(object, "", "");
  }

  public <P> P decrypt(P object) throws Exception {
    return decrypt(object, "", "");
  }

  public DiffieHellmanExchangeResponse encrypt(DiffieHellmanExchangeResponse object) throws Exception {
    crypto.getFromQueue(DiffieHellmanExchangeRequest.class);
    return object;
  }

  public DiffieHellmanExchangeRequest decrypt(DiffieHellmanExchangeRequest object) throws Exception {
    return object;
  }

  public AuthenticateResponse encrypt(AuthenticateResponse object) throws Exception {
    String client = crypto.getFromQueue(AuthenticateRequest.class);
    return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public AuthenticateRequest decrypt(AuthenticateRequest object) throws Exception {
    String client = crypto.getFromQueue(AuthenticateRequest.class);
    return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }
}
