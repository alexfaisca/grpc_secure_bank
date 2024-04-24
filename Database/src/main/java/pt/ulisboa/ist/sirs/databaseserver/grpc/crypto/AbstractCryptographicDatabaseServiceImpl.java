package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.databaseserver.DatabaseServerImpl;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicDatabaseServiceImpl {
  public final ServerServiceDefinition bindService(DatabaseServerCryptographicManager crypto, DatabaseServerImpl serverImpl) {
    final MethodDescriptor<AuthenticateRequest, AuthenticateResponse> METHOD_AUTHENTICATE =
      DatabaseServiceGrpc.getAuthenticateMethod()
        .toBuilder(
          DatabaseServiceGrpc.getAuthenticateMethod().getRequestMarshaller(),
          crypto.marshallerForDatabaseAuth(AuthenticateResponse.getDefaultInstance(), DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<StillAliveRequest, StillAliveResponse> METHOD_STILL_ALIVE =
      DatabaseServiceGrpc.getStillAliveMethod()
        .toBuilder(
          crypto.marshallerForDatabaseAuth(StillAliveRequest.getDefaultInstance(), DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName()),
          crypto.marshallerForDatabaseAuth(StillAliveResponse.getDefaultInstance(), DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<CreateAccountRequest, Ack> METHOD_CREATE_ACCOUNT =
      DatabaseServiceGrpc.getCreateAccountMethod()
        .toBuilder(
          crypto.marshallerForDatabase(CreateAccountRequest.getDefaultInstance(), DatabaseServiceGrpc.getCreateAccountMethod().getFullMethodName()),
          crypto.marshallerForDatabase(Ack.getDefaultInstance(), DatabaseServiceGrpc.getCreateAccountMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<DeleteAccountRequest, Ack> METHOD_DELETE_ACCOUNT =
      DatabaseServiceGrpc.getDeleteAccountMethod()
        .toBuilder(
          crypto.marshallerForDatabase(DeleteAccountRequest.getDefaultInstance(), DatabaseServiceGrpc.getDeleteAccountMethod().getFullMethodName()),
          crypto.marshallerForDatabase(Ack.getDefaultInstance(), DatabaseServiceGrpc.getDeleteAccountMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<BalanceRequest, BalanceResponse> METHOD_BALANCE =
      DatabaseServiceGrpc.getBalanceMethod()
        .toBuilder(
          crypto.marshallerForDatabase(BalanceRequest.getDefaultInstance(), DatabaseServiceGrpc.getBalanceMethod().getFullMethodName()),
          crypto.marshallerForDatabase(BalanceResponse.getDefaultInstance(), DatabaseServiceGrpc.getBalanceMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<GetMovementsRequest, GetMovementsResponse> METHOD_GET_MOVEMENTS =
      DatabaseServiceGrpc.getGetMovementsMethod()
        .toBuilder(
          crypto.marshallerForDatabase(GetMovementsRequest.getDefaultInstance(), DatabaseServiceGrpc.getGetMovementsMethod().getFullMethodName()),
          crypto.marshallerForDatabase(GetMovementsResponse.getDefaultInstance(), DatabaseServiceGrpc.getGetMovementsMethod().getFullMethodName())
    ).build();
    final MethodDescriptor<OrderPaymentRequest, Ack> METHOD_ORDER_PAYMENTS =
      DatabaseServiceGrpc.getOrderPaymentMethod()
        .toBuilder(
          crypto.marshallerForDatabase(OrderPaymentRequest.getDefaultInstance(), DatabaseServiceGrpc.getOrderPaymentMethod().getFullMethodName()),
          crypto.marshallerForDatabase(Ack.getDefaultInstance(), DatabaseServiceGrpc.getOrderPaymentMethod().getFullMethodName())
    ).build();
    ServerServiceDefinition orig = serverImpl.bindService();
    return ServerServiceDefinition.builder(orig.getServiceDescriptor().getName())
      .addMethod(METHOD_AUTHENTICATE, asyncUnaryCall(serverImpl::authenticate))
      .addMethod(METHOD_STILL_ALIVE, asyncUnaryCall(serverImpl::stillAlive))
      .addMethod(METHOD_CREATE_ACCOUNT, asyncUnaryCall(serverImpl::createAccount))
      .addMethod(METHOD_DELETE_ACCOUNT, asyncUnaryCall(serverImpl::deleteAccount))
      .addMethod(METHOD_BALANCE, asyncUnaryCall(serverImpl::balance))
      .addMethod(METHOD_GET_MOVEMENTS, asyncUnaryCall(serverImpl::getMovements))
      .addMethod(METHOD_ORDER_PAYMENTS, asyncUnaryCall(serverImpl::orderPayment))
      .build();
  }
}
