package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.stub.AbstractStub;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static io.grpc.stub.ClientCalls.blockingUnaryCall;

public class AuthenticationServerCryptographicStub extends AbstractStub<AuthenticationServerCryptographicStub> {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForAuth(T message) {
    return new MethodDescriptor.Marshaller<>() {
      @Override
      public InputStream stream(T value) {
        try {
          return new ByteArrayInputStream(crypto.encryptAuth(value.toByteArray()));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }

      @Override
      @SuppressWarnings("unchecked")
      public T parse(InputStream inputStream) {
        try {
          return (T) message.newBuilderForType().mergeFrom(crypto.decryptAuth(inputStream.readAllBytes())).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
  final MethodDescriptor<DiffieHellmanExchangeRequest, DiffieHellmanExchangeResponse> METHOD_DIFFIE_HELLMAN =
    AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().toBuilder(
      AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getRequestMarshaller(),
      AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getResponseMarshaller()
  ).build();
  final MethodDescriptor<LookupRequest, LookupResponse> METHOD_LOOKUP =
    AuthenticationServerServiceGrpc.getLookupMethod().toBuilder(
      marshallerForAuth(LookupRequest.getDefaultInstance()),
      marshallerForAuth(LookupResponse.getDefaultInstance())
  ).build();
  final MethodDescriptor<AuthenticateRequest, AuthenticateResponse> METHOD_AUTHENTICATE =
    AuthenticationServerServiceGrpc.getAuthenticateMethod().toBuilder(
      marshallerForAuth(AuthenticateRequest.getDefaultInstance()),
      marshallerForAuth(AuthenticateResponse.getDefaultInstance())
  ).build();
  private final ClientCryptographicManager crypto;

  public AuthenticationServerCryptographicStub(Channel channel, ClientCryptographicManager crypto) {
    super(channel);
    this.crypto = crypto;
  }

  public AuthenticationServerCryptographicStub(Channel channel, CallOptions callOptions, ClientCryptographicManager crypto) {
    super(channel, callOptions);
    this.crypto = crypto;
  }

  @Override
  protected AuthenticationServerCryptographicStub build(Channel channel, CallOptions callOptions) {
    return new AuthenticationServerCryptographicStub(channel, callOptions, new ClientCryptographicManager());
  }

  public DiffieHellmanExchangeResponse diffieHellmanExchange(DiffieHellmanExchangeRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_DIFFIE_HELLMAN, getCallOptions(), request);
  }

  public LookupResponse lookup(LookupRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_LOOKUP, getCallOptions(), request);
  }

  public AuthenticateResponse authenticate(AuthenticateRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_AUTHENTICATE, getCallOptions(), request);
  }
}
