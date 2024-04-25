package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import io.grpc.*;
import io.grpc.MethodDescriptor.Marshaller;
import com.google.protobuf.Message;

import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.databaseserver.dto.TicketDto;
import pt.ulisboa.ist.sirs.dto.Ticket;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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
  public <T extends Message> Marshaller<T> marshallerForDatabaseAuth(T message, String fullMethodName) {
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
          return (T) message.newBuilderForType().mergeFrom(decryptByteArray(inputStream.readAllBytes(), methodName)).build();
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
  private final Map<String, Long> nonces = new HashMap<>();

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

  public long initializeNonce() {
    long nonce = (new Random()).nextLong();
    nonces.put(crypto.getFromQueue(DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName()), nonce);
    return nonce;
  }

  public boolean checkNonce(Long nonce) {
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

  public TicketDto unbundleTicket(byte[] ticket) throws Exception {
    Ticket unbundled = Base.KeyManager.unbundleTicket(Operations.decryptData(
      Base.readSecretKey(buildAuthKeyPath()), ticket, Base.readIv(buildAuthIVPath())
    ));
    return new TicketDto(unbundled.sourceHash(), unbundled.sessionKey(), unbundled.sessionIV());
  }
}
