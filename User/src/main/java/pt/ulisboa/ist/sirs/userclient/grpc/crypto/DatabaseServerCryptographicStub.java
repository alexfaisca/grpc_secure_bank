package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import com.google.protobuf.Message;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.stub.AbstractStub;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServiceGrpc;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static io.grpc.stub.ClientCalls.blockingUnaryCall;

public final class DatabaseServerCryptographicStub extends AbstractStub<DatabaseServerCryptographicStub> {
  public <T extends Message> MethodDescriptor.Marshaller<T> marshallerFor(T message) {
    return new MethodDescriptor.Marshaller<>() {
      @Override
      public InputStream stream(T value) {
        try {
          return new ByteArrayInputStream(crypto.encrypt(value.toByteArray()));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }

      @Override
      @SuppressWarnings("unchecked")
      public T parse(InputStream inputStream) {
        try {
          byte[] response = inputStream.readAllBytes();
          if (crypto.check(response))
            throw new TamperedMessageException();
          return (T) message.newBuilderForType().mergeFrom(crypto.decrypt(response)).build();
        } catch (IOException e) {
          throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
  final MethodDescriptor<CreateAccountRequest, Ack> METHOD_CREATE_ACCOUNT =
    DatabaseServiceGrpc.getCreateAccountMethod().toBuilder(
      marshallerFor(CreateAccountRequest.getDefaultInstance()),
      marshallerFor(Ack.getDefaultInstance())
  ).build();
  final MethodDescriptor<DeleteAccountRequest, Ack> METHOD_DELETE_ACCOUNT =
    DatabaseServiceGrpc.getDeleteAccountMethod().toBuilder(
      marshallerFor(DeleteAccountRequest.getDefaultInstance()),
      marshallerFor(Ack.getDefaultInstance())
  ).build();
  final MethodDescriptor<BalanceRequest, BalanceResponse> METHOD_BALANCE =
    DatabaseServiceGrpc.getBalanceMethod().toBuilder(
      marshallerFor(BalanceRequest.getDefaultInstance()),
      marshallerFor(BalanceResponse.getDefaultInstance())
  ).build();
  final MethodDescriptor<GetMovementsRequest, GetMovementsResponse> METHOD_GET_MOVEMENTS =
    DatabaseServiceGrpc.getGetMovementsMethod().toBuilder(
      marshallerFor(GetMovementsRequest.getDefaultInstance()),
      marshallerFor(GetMovementsResponse.getDefaultInstance())
  ).build();
  final MethodDescriptor<OrderPaymentRequest, Ack> METHOD_ORDER_PAYMENT =
    DatabaseServiceGrpc.getOrderPaymentMethod().toBuilder(
      marshallerFor(OrderPaymentRequest.getDefaultInstance()),
      marshallerFor(Ack.getDefaultInstance())
  ).build();
  private final DatabaseServiceGrpc.DatabaseServiceBlockingStub origStub;
  private final ClientCryptographicManager crypto;

  public DatabaseServerCryptographicStub(Channel channel, ClientCryptographicManager crypto) {
    super(channel);
    this.origStub = DatabaseServiceGrpc.newBlockingStub(channel);
    this.crypto = crypto;
  }

  public DatabaseServerCryptographicStub(Channel channel, CallOptions callOptions, ClientCryptographicManager crypto) {
    super(channel, callOptions);
    this.origStub = DatabaseServiceGrpc.newBlockingStub(channel);
    this.crypto = crypto;
  }

  @Override
  protected DatabaseServerCryptographicStub build(Channel channel, CallOptions callOptions) {
    return new DatabaseServerCryptographicStub(channel, callOptions, new ClientCryptographicManager());
  }

  public AuthenticateResponse authenticate(AuthenticateRequest request) {
    return origStub.authenticate(request);
  }

  public StillAliveResponse stillAlive(StillAliveRequest request) {
    return origStub.stillAlive(request);
  }

  public Ack createAccount(CreateAccountRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_CREATE_ACCOUNT, getCallOptions(), request);
  }

  public Ack deleteAccount(DeleteAccountRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_DELETE_ACCOUNT, getCallOptions(), request);
  }

  public BalanceResponse balance(DatabaseServer.BalanceRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_BALANCE, getCallOptions(), request);
  }

  public GetMovementsResponse getMovements(GetMovementsRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_GET_MOVEMENTS, getCallOptions(), request);
  }

  public Ack orderPayment(OrderPaymentRequest request) {
    return blockingUnaryCall(getChannel(), METHOD_ORDER_PAYMENT, getCallOptions(), request);
  }
}