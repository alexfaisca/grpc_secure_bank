package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import pt.ulisboa.ist.sirs.authenticationserver.NamingServerImpl;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicNamingServiceImpl {
  public final ServerServiceDefinition bindService(NamingServerCryptographicManager crypto, NamingServerImpl serverImpl) {
    final MethodDescriptor<EncryptedKeyExchangeChallengeRequest, EncryptedKeyExchangeChallengeResponse> METHOD_EKE_CHALLENGE =
      NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod()
      .toBuilder(
        crypto.marshallerForNamingServer(EncryptedKeyExchangeChallengeRequest.getDefaultInstance(), NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName()),
        crypto.marshallerForNamingServer(EncryptedKeyExchangeChallengeResponse.getDefaultInstance(), NamingServerServiceGrpc.getEncryptedKeyExchangeChallengeMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<RegisterRequest, Ack> METHOD_REGISTER_SERVER =
      NamingServerServiceGrpc.getRegisterMethod()
        .toBuilder(
          crypto.marshallerForNamingServer(RegisterRequest.getDefaultInstance(), NamingServerServiceGrpc.getRegisterMethod().getFullMethodName()),
          crypto.marshallerForNamingServer(Ack.getDefaultInstance(), NamingServerServiceGrpc.getRegisterMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<LookupRequest, LookupResponse> METHOD_LOOKUP_SERVER =
      NamingServerServiceGrpc.getLookupMethod()
        .toBuilder(
          crypto.marshallerForNamingServer(LookupRequest.getDefaultInstance(), NamingServerServiceGrpc.getLookupMethod().getFullMethodName()),
          crypto.marshallerForNamingServer(LookupResponse.getDefaultInstance(), NamingServerServiceGrpc.getLookupMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<DeleteRequest, Ack> METHOD_DELETE_SERVER =
      NamingServerServiceGrpc.getDeleteMethod()
        .toBuilder(
          crypto.marshallerForNamingServer(DeleteRequest.getDefaultInstance(), NamingServerServiceGrpc.getDeleteMethod().getFullMethodName()),
          crypto.marshallerForNamingServer(Ack.getDefaultInstance(), NamingServerServiceGrpc.getDeleteMethod().getFullMethodName())
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
