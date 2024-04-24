package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import pt.ulisboa.ist.sirs.authenticationserver.AuthenticationServerImpl;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicAuthenticationServiceImpl {
  public final ServerServiceDefinition bindService(AuthenticationServerCryptographicManager crypto, AuthenticationServerImpl serverImpl) {
    final MethodDescriptor<DiffieHellmanExchangeRequest, DiffieHellmanExchangeResponse> METHOD_DIFFIE_HELLMAN =
      AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().toBuilder(
        AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getRequestMarshaller(),
        AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getResponseMarshaller()
    ).build();
    final MethodDescriptor<AuthenticateRequest, AuthenticateResponse> METHOD_AUTHENTICATE =
      AuthenticationServerServiceGrpc.getAuthenticateMethod().toBuilder(
        crypto.marshallerForNamingServer(AuthenticateRequest.getDefaultInstance(), AuthenticationServerServiceGrpc.getAuthenticateMethod().getFullMethodName()),
        crypto.marshallerForNamingServer(AuthenticateResponse.getDefaultInstance(), AuthenticationServerServiceGrpc.getAuthenticateMethod().getFullMethodName())
    ).build();
    ServerServiceDefinition orig = serverImpl.bindService();
    return ServerServiceDefinition.builder(orig.getServiceDescriptor().getName())
            .addMethod(METHOD_DIFFIE_HELLMAN, asyncUnaryCall(serverImpl::diffieHellmanExchange))
            .addMethod(METHOD_AUTHENTICATE, asyncUnaryCall(serverImpl::authenticate))
            .build();
  }
}
