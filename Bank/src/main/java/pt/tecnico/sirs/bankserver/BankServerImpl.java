package pt.tecnico.sirs.bankserver;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.tecnico.sirs.contract.bankserver.BankServer.*;
import pt.tecnico.sirs.contract.bankserver.BankingServiceGrpc.BankingServiceImplBase;
import pt.tecnico.sirs.bankserver.domain.BankState;

public final class BankServerImpl extends BankingServiceImplBase {
  private final boolean debug;
  private final BankState state;

  public BankServerImpl(BankState bank, boolean debug) {
    this.debug = debug;
    this.state = bank;
  }

  private boolean isDebug() {
    return debug;
  }

  @Override
  public void authenticate(AuthenticateRequest request, StreamObserver<AuthenticateResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: parse and delegate request");
      byte[] rawResponse = state.authenticate(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: serialize and send response");
      responseObserver.onNext(AuthenticateResponse.newBuilder().setResponse(ByteString.copyFrom(rawResponse)).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void stillAlive(StillAliveRequest request, StreamObserver<StillAliveResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: parse and delegate request");
      byte[] rawResponse = state.stillAlive(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: serialize and send response");
      responseObserver.onNext(StillAliveResponse.newBuilder().setResponse(ByteString.copyFrom(rawResponse)).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void createAccount(CreateAccountRequest request, StreamObserver<CreateAccountResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");
      state.createAccount(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: encrypt serialize and send response");
      responseObserver.onNext(CreateAccountResponse.newBuilder().build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void deleteAccount(DeleteAccountRequest request, StreamObserver<DeleteAccountResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");
      state.deleteAccount(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: encrypt serialize and send response");
      responseObserver.onNext(DeleteAccountResponse.newBuilder().build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void balance(BalanceRequest request, StreamObserver<BalanceResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");
      responseObserver.onNext(BalanceResponse.newBuilder().setResponse(
          ByteString.copyFrom(
              state.balance(request.getRequest().toByteArray())))
          .build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void addExpense(AddExpenseRequest request, StreamObserver<AddExpenseResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");
      if (isDebug())
        System.out.println("\tBankServerImpl: delegate request");
      state.addExpense(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: encrypt serialize and send response");
      responseObserver.onNext(AddExpenseResponse.newBuilder().build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void getMovements(GetMovementsRequest request, StreamObserver<GetMovementsResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");
      responseObserver.onNext(GetMovementsResponse.newBuilder().setResponse(
          ByteString.copyFrom(
              state.getMovements(request.getRequest().toByteArray())))
          .build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }

  @Override
  public void orderPayment(OrderPaymentRequest request, StreamObserver<OrderPaymentResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tBankServerImpl: decrypt deserialize parse request");

      state.orderPayment(request.getRequest().toByteArray());

      if (isDebug())
        System.out.println("\tBankServerImpl: encrypt serialize and send response");
      responseObserver.onNext(OrderPaymentResponse.newBuilder().build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      System.out.println(e.getMessage());
      responseObserver.onError(e);
    }
  }
}
