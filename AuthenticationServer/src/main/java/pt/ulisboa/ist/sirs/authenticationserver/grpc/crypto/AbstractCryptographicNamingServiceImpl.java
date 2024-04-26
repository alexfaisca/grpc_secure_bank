package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.ulisboa.ist.sirs.authenticationserver.NamingServerImpl;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicNamingServiceImpl {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForNamingServer(
    T message, String fullMethodName, NamingServerCryptographicManager crypto
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
          byte[] request = inputStream.readAllBytes();
          if (crypto.checkByteArray(request, methodName))
            throw new TamperedMessageException();
          return (T) message.newBuilderForType().mergeFrom(crypto.decryptByteArray(request, methodName)).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
  public final ServerServiceDefinition bindService(NamingServerCryptographicManager crypto, NamingServerImpl serverImpl) {
    final MethodDescriptor<EncryptedKeyExchangeChallengeRequest, EncryptedKeyExchangeChallengeResponse> METHOD_EKE_CHALLENGE =
      NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod()
      .toBuilder(
        marshallerForNamingServer(
          EncryptedKeyExchangeChallengeRequest.getDefaultInstance(),
          NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName(),
          crypto
        ),
        marshallerForNamingServer(
          EncryptedKeyExchangeChallengeResponse.getDefaultInstance(),
          NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName(),
          crypto
        )
    ).build();
    final MethodDescriptor<RegisterRequest, Ack> METHOD_REGISTER_SERVER =
      NamingServerServiceGrpc.getRegisterMethod()
        .toBuilder(
          marshallerForNamingServer(
            RegisterRequest.getDefaultInstance(),
            NamingServerServiceGrpc.getRegisterMethod().getFullMethodName(),
            crypto
          ),
          marshallerForNamingServer(
            Ack.getDefaultInstance(),
            NamingServerServiceGrpc.getRegisterMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<LookupRequest, LookupResponse> METHOD_LOOKUP_SERVER =
      NamingServerServiceGrpc.getLookupMethod()
        .toBuilder(
          marshallerForNamingServer(
            LookupRequest.getDefaultInstance(),
            NamingServerServiceGrpc.getLookupMethod().getFullMethodName(),
            crypto
          ),
          marshallerForNamingServer(
            LookupResponse.getDefaultInstance(),
            NamingServerServiceGrpc.getLookupMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<DeleteRequest, Ack> METHOD_DELETE_SERVER =
      NamingServerServiceGrpc.getDeleteMethod()
        .toBuilder(
          marshallerForNamingServer(
            DeleteRequest.getDefaultInstance(),
            NamingServerServiceGrpc.getDeleteMethod().getFullMethodName(),
            crypto
          ),
          marshallerForNamingServer(
            Ack.getDefaultInstance(),
            NamingServerServiceGrpc.getDeleteMethod().getFullMethodName(),
            crypto
          )
    ).build();
    ServerServiceDefinition orig = serverImpl.bindService();
    return ServerServiceDefinition.builder(orig.getServiceDescriptor().getName())
      .addMethod(NamingServerServiceGrpc.getInitiateEncryptedKeyExchangeMethod(), asyncUnaryCall(serverImpl::initiateEncryptedKeyExchange))
      .addMethod(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod(), asyncUnaryCall(serverImpl::encryptedKeyExchange))
      .addMethod(METHOD_EKE_CHALLENGE, asyncUnaryCall(serverImpl::encryptedKeyExchangeChallenge))
      .addMethod(METHOD_REGISTER_SERVER, asyncUnaryCall(serverImpl::register))
      .addMethod(METHOD_LOOKUP_SERVER, asyncUnaryCall(serverImpl::lookup))
      .addMethod(METHOD_DELETE_SERVER, asyncUnaryCall(serverImpl::delete))
      .build();
  }
}
