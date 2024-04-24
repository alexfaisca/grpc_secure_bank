package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class AuthenticationServerCryptographicManager extends AuthenticationServerCryptographicCore {
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
          return (T) message.newBuilderForType().mergeFrom(decryptByteArray(inputStream.readAllBytes(), methodName)).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
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

  public String getClientHash(String methodName) {
      return crypto.getClientHash(methodName);
  }

  public byte[] encryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return encryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }

  public byte[] decryptByteArray(byte[] object, String methodName) throws Exception {
    String client = getClientHash(methodName);
    return decryptByteArray(object, buildSymmetricKeyPath(client), buildIVPath(client));
  }
}
