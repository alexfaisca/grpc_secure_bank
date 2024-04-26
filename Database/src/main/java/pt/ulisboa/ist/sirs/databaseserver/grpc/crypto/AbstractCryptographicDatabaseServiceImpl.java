package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.databaseserver.DatabaseServerImpl;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static io.grpc.stub.ServerCalls.asyncUnaryCall;

public abstract class AbstractCryptographicDatabaseServiceImpl {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForDatabase(
    T message, String fullMethodName, DatabaseServerCryptographicManager crypto
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
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerForDatabaseAuth(
    T message, String fullMethodName, DatabaseServerCryptographicManager crypto
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
  public final ServerServiceDefinition bindService(DatabaseServerCryptographicManager crypto, DatabaseServerImpl serverImpl) {
    final MethodDescriptor<AuthenticateRequest, AuthenticateResponse> METHOD_AUTHENTICATE =
      DatabaseServiceGrpc.getAuthenticateMethod()
        .toBuilder(
          DatabaseServiceGrpc.getAuthenticateMethod().getRequestMarshaller(),
          marshallerForDatabaseAuth(
            AuthenticateResponse.getDefaultInstance(),
            DatabaseServiceGrpc.getAuthenticateMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<StillAliveRequest, StillAliveResponse> METHOD_STILL_ALIVE =
      DatabaseServiceGrpc.getStillAliveMethod()
        .toBuilder(
          marshallerForDatabaseAuth(
            StillAliveRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabaseAuth(
            StillAliveResponse.getDefaultInstance(),
            DatabaseServiceGrpc.getStillAliveMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<CreateAccountRequest, Ack> METHOD_CREATE_ACCOUNT =
      DatabaseServiceGrpc.getCreateAccountMethod()
        .toBuilder(
          marshallerForDatabase(
            CreateAccountRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getCreateAccountMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabase(
            Ack.getDefaultInstance(),
            DatabaseServiceGrpc.getCreateAccountMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<DeleteAccountRequest, Ack> METHOD_DELETE_ACCOUNT =
      DatabaseServiceGrpc.getDeleteAccountMethod()
        .toBuilder(
          marshallerForDatabase(
            DeleteAccountRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getDeleteAccountMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabase(
            Ack.getDefaultInstance(),
            DatabaseServiceGrpc.getDeleteAccountMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<BalanceRequest, BalanceResponse> METHOD_BALANCE =
      DatabaseServiceGrpc.getBalanceMethod()
        .toBuilder(
          marshallerForDatabase(
            BalanceRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getBalanceMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabase(
            BalanceResponse.getDefaultInstance(),
            DatabaseServiceGrpc.getBalanceMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<GetMovementsRequest, GetMovementsResponse> METHOD_GET_MOVEMENTS =
      DatabaseServiceGrpc.getGetMovementsMethod()
        .toBuilder(
          marshallerForDatabase(
            GetMovementsRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getGetMovementsMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabase(
            GetMovementsResponse.getDefaultInstance(),
            DatabaseServiceGrpc.getGetMovementsMethod().getFullMethodName(),
            crypto
          )
    ).build();
    final MethodDescriptor<OrderPaymentRequest, Ack> METHOD_ORDER_PAYMENTS =
      DatabaseServiceGrpc.getOrderPaymentMethod()
        .toBuilder(
          marshallerForDatabase(
            OrderPaymentRequest.getDefaultInstance(),
            DatabaseServiceGrpc.getOrderPaymentMethod().getFullMethodName(),
            crypto
          ),
          marshallerForDatabase(
            Ack.getDefaultInstance(),
            DatabaseServiceGrpc.getOrderPaymentMethod().getFullMethodName(),
            crypto
          )
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
