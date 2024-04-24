package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import io.grpc.*;
import io.grpc.MethodDescriptor.Marshaller;
import com.google.protobuf.Message;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class DatabaseServerCryptographicManager extends DatabaseServerCryptographicCore implements Base.KeyManager {
  public <T extends Message> Marshaller<T> marshallerForDatabase(T message, String fullMethodName) {
    return new Marshaller<>() {
      private final String methodName = fullMethodName;
      @Override
      public InputStream stream(T value) {
        try {
          return new ByteArrayInputStream(encryptByteArray(value.toByteArray(), methodName));
        } catch (Exception e) {
          throw new StatusRuntimeException(Status.INTERNAL.withDescription(Arrays.toString(e.getStackTrace())));
        }
      }

      @Override
      @SuppressWarnings("unchecked")
      public T parse(InputStream inputStream) {
        try {
          byte[] request = inputStream.readAllBytes();
          if (checkByteArray(request, methodName))
            throw new TamperedMessageException();
          return (T) message.newBuilderForType().mergeFrom(decryptByteArray(request, methodName)).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
  private final String publicKeyPath;
  private final String privateKeyPath;
  private final DatabaseServerCryptographicInterceptor crypto;
  private final Map<String, Integer> nonces = new HashMap<>();

  public DatabaseServerCryptographicManager(
      DatabaseServerCryptographicInterceptor crypto,
      String publicKeyPath,
      String privateKeyPath) {
    super();
    this.publicKeyPath = publicKeyPath;
    this.privateKeyPath = privateKeyPath;
    this.crypto = crypto;
  }

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  public String getPublicKeyPath() {
    return this.publicKeyPath;
  }

  public String getPrivateKeyPath() {
    return this.privateKeyPath;
  }

  public String buildAuthKeyPath() {
    return "resources/crypto/auth/symmetricKey";
  }

  public String buildAuthIVPath() {
    return "resources/crypto/auth/iv";
  }

  private String buildSessionKeyPath(String client) {
    return "resources/crypto/session/" + client + "/sessionKey";
  }

  private String buildSessionIVPath(String client) {
    return "resources/crypto/session/" + client + "/iv";
  }

  private String buildSessionPublicKeyPath(String client) {
    return "resources/crypto/session/" + client + "/publicKey";
  }

  public void createSession(byte[] sessionKey, byte[] iv) {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName());
    File clientDirectory = new File("resources/crypto/session/" + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
    Utils.writeBytesToFile(sessionKey, buildSessionKeyPath(client));
    Utils.writeBytesToFile(iv, buildSessionIVPath(client));
  }

  public void setNonce(Integer nonce) {
    nonces.put(crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName()), nonce);
  }

  public Integer getNonce() {
    return nonces.get(crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName()));
  }

  public boolean checkNonce(Integer nonce) {
    boolean result = false;
    if (nonces.containsKey(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName()))) {
      result = nonces.get(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName())).equals(nonce);
      nonces.remove(crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName()));
    }
    return result;
  }

  public void validateSession(byte[] publicKey) {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName());
    Utils.writeBytesToFile(publicKey, buildSessionPublicKeyPath(client));
  }

  public byte[] decryptPassword(String password) {
    return Utils.hexToByte(password);
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSessionKeyPath(client), getPrivateKeyPath(), buildSessionIVPath(client));
  }

  public boolean checkByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return !checkByteArray(object, buildSessionKeyPath(client), buildSessionPublicKeyPath(client), buildSessionIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSessionKeyPath(client), buildSessionIVPath(client));
  }

  @SuppressWarnings("all")
  public AuthenticateRequest decrypt(AuthenticateRequest object) throws Exception {
    return decrypt(object, buildAuthKeyPath(), buildAuthIVPath());
  }

  public AuthenticateResponse encrypt(AuthenticateResponse object) throws Exception {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName());
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(), buildSessionIVPath(client));
  }

  public StillAliveResponse encrypt(StillAliveResponse object) throws Exception {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName());
    return encrypt(object, buildSessionKeyPath(client), getPrivateKeyPath(), buildSessionIVPath(client));
  }

  public boolean check(StillAliveRequest object) throws Exception {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName());
    return check(object, buildSessionKeyPath(client), buildSessionPublicKeyPath(client), buildSessionIVPath(client));
  }

  public StillAliveRequest decrypt(StillAliveRequest object) throws Exception {
    String client = crypto.getFromQueue(DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName());
    return decrypt(object, buildSessionKeyPath(client), buildSessionIVPath(client));
  }
}
