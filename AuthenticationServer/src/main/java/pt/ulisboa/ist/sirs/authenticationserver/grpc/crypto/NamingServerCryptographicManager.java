package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
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

public class NamingServerCryptographicManager extends NamingServerCryptographicCore {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForNamingServer(T message, String fullMethodName) {
    return new MethodDescriptor.Marshaller<>() {
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
  private final ServerCryptographicInterceptor crypto;
  private final Map<String, Long> nonces = new HashMap<>();
  private static final String CLIENT_CACHE_DIR = "resources/crypto/server/";

  public NamingServerCryptographicManager(ServerCryptographicInterceptor crypto) {
      this.crypto = crypto;
  }

  public String getPublicKeyPath() {
      return Base.CryptographicCore.getPublicKeyPath();
  }

  public String getPrivateKeyPath() {
      return Base.CryptographicCore.getPrivateKeyPath();
  }

  public boolean checkServerCache(String client) {
    File clientDirectory = new File(CLIENT_CACHE_DIR + client + "/");
    return !clientDirectory.exists();
  }

  public String buildSymmetricKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/symmetricKey";
  }

  public String buildIVPath(String client) {
      return CLIENT_CACHE_DIR + client + "/iv";
  }

  public String buildPublicKeyPath(String client) {
      return CLIENT_CACHE_DIR + client + "/publicKey";
  }

  public String getClientHash(String methodName) {
    return crypto.getClientHash(methodName);
  }

  public void setNonce(Long nonce) {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    nonces.put(client, nonce);
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

  public void validateSession(byte[] clientPublicKey) {
    String client = getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());
    File clientDirectory = new File("resources/crypto/server/" + client + "/");
    if (!clientDirectory.exists())
      if (!clientDirectory.mkdirs())
        throw new RuntimeException("Could not store client key");
    Utils.writeBytesToFile(clientPublicKey, buildPublicKeyPath(client));
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
}
