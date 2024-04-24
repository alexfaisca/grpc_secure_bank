package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.stub.AbstractStub;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static io.grpc.stub.ClientCalls.blockingUnaryCall;

public class NamingServerCryptographicStub extends AbstractStub<NamingServerCryptographicStub> {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerFor(T message) {
    return new MethodDescriptor.Marshaller<>() {
      @Override
      public InputStream stream(T value) {
        try {
          return new ByteArrayInputStream(crypto.encryptByteArray(value.toByteArray()));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }

      @Override
      @SuppressWarnings("unchecked")
      public T parse(InputStream inputStream) {
        try {
          byte[] response = inputStream.readAllBytes();
          if (crypto.checkByteArray(response))
            throw new TamperedMessageException();
          return (T) message.newBuilderForType().mergeFrom(crypto.decryptByteArray(response)).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }

  final MethodDescriptor<EncryptedKeyExchangeChallengeRequest, EncryptedKeyExchangeChallengeResponse> METHOD_EKE_CHALLENGE =
    NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod()
    .toBuilder(
      marshallerFor(EncryptedKeyExchangeChallengeRequest.getDefaultInstance()),
      marshallerFor(EncryptedKeyExchangeChallengeResponse.getDefaultInstance())
  ).build();
  final MethodDescriptor<RegisterRequest, Ack> METHOD_REGISTER_SERVER =
    NamingServerServiceGrpc.getRegisterMethod()
    .toBuilder(
      marshallerFor(RegisterRequest.getDefaultInstance()),
      marshallerFor(Ack.getDefaultInstance())
  ).build();
  final MethodDescriptor<LookupRequest, LookupResponse> METHOD_LOOKUP_SERVER =
    NamingServerServiceGrpc.getLookupMethod()
      .toBuilder(
        marshallerFor(LookupRequest.getDefaultInstance()),
        marshallerFor(LookupResponse.getDefaultInstance())
  ).build();
  final MethodDescriptor<DeleteRequest, Ack> METHOD_DELETE_SERVER =
    NamingServerServiceGrpc.getDeleteMethod()
      .toBuilder(
        marshallerFor(DeleteRequest.getDefaultInstance()),
        marshallerFor(Ack.getDefaultInstance())
  ).build();

  private final NamingServerServiceGrpc.NamingServerServiceBlockingStub origStub;
  private final AuthenticationClientCryptographicManager crypto;

  public NamingServerCryptographicStub(Channel channel, AuthenticationClientCryptographicManager crypto) {
    super(channel);
    this.origStub = NamingServerServiceGrpc.newBlockingStub(channel);
    this.crypto = crypto;
  }

  public NamingServerCryptographicStub(Channel channel, CallOptions callOptions, AuthenticationClientCryptographicManager crypto) {
    super(channel, callOptions);
    this.origStub = NamingServerServiceGrpc.newBlockingStub(channel);
    this.crypto = crypto;
  }

  @Override
  protected NamingServerCryptographicStub build(Channel channel, CallOptions callOptions) {
    return new NamingServerCryptographicStub(channel, callOptions, new AuthenticationClientCryptographicManager());
  }

  public InitiateEncryptedKeyExchangeResponse initiateEncryptedKeyExchange(Ack request) {
    return origStub.initiateEncryptedKeyExchange(request);
  }

  public EncryptedKeyExchangeResponse encryptedKeyExchange(EncryptedKeyExchangeRequest request) {
    return origStub.encryptedKeyExchange(request);
  }

  public EncryptedKeyExchangeChallengeResponse encryptedKeyExchangeChallenge(EncryptedKeyExchangeChallengeRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_EKE_CHALLENGE, getCallOptions(), request);
  }

  public Ack register(RegisterRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_REGISTER_SERVER, getCallOptions(), request);
  }

  public LookupResponse lookup(LookupRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_LOOKUP_SERVER, getCallOptions(), request);
  }

  public Ack delete(DeleteRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_DELETE_SERVER, getCallOptions(), request);
  }


}
