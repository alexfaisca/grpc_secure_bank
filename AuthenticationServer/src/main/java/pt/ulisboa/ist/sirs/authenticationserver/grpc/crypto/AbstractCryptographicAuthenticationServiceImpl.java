package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.ulisboa.ist.sirs.authenticationserver.AuthenticationServerImpl;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicAuthenticationServiceImpl {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForAuthServer(
    T message, String fullMethodName, AuthenticationServerCryptographicManager crypto
  ) {
    return new MethodDescriptor.Marshaller<>() {
      private final String methodName = fullMethodName;
      @Override
      public InputStream stream(T value) {
        try {
          return new ByteArrayInputStream(crypto.encryptByteArray(value.toByteArray(), methodName));
        } catch (Exception e) {
          throw new StatusRuntimeException(Status.INTERNAL.withDescription(Arrays.toString(e.getStackTrace())));
        }
      }
      @Override
      @SuppressWarnings("unchecked")
      public T parse(InputStream inputStream) {
        try {
          System.out.println(methodName);
          return (T) message.newBuilderForType().mergeFrom(
            crypto.decryptByteArray(inputStream.readAllBytes(), methodName)
          ).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
  public final ServerServiceDefinition bindService(
    AuthenticationServerCryptographicManager crypto, AuthenticationServerImpl serverImpl
  ) {
    final MethodDescriptor<DiffieHellmanExchangeRequest, DiffieHellmanExchangeResponse> METHOD_DIFFIE_HELLMAN =
      AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().toBuilder(
        AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getRequestMarshaller(),
        AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getResponseMarshaller()
    ).build();
    final MethodDescriptor<AuthenticateRequest, AuthenticateResponse> METHOD_AUTHENTICATE =
      AuthenticationServerServiceGrpc.getAuthenticateMethod().toBuilder(
        marshallerForAuthServer(
          AuthenticateRequest.getDefaultInstance(),
          AuthenticationServerServiceGrpc.getAuthenticateMethod().getFullMethodName(),
          crypto
        ),
        marshallerForAuthServer(
          AuthenticateResponse.getDefaultInstance(),
          AuthenticationServerServiceGrpc.getAuthenticateMethod().getFullMethodName(),
          crypto
        )
    ).build();
    ServerServiceDefinition orig = serverImpl.bindService();
    return ServerServiceDefinition.builder(orig.getServiceDescriptor().getName())
            .addMethod(METHOD_DIFFIE_HELLMAN, asyncUnaryCall(serverImpl::diffieHellmanExchange))
            .addMethod(METHOD_AUTHENTICATE, asyncUnaryCall(serverImpl::authenticate))
            .build();
  }
}
