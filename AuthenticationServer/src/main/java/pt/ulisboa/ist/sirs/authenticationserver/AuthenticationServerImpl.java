package pt.ulisboa.ist.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.BindableService;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.authenticationserver.dto.AuthTicket;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AbstractCryptographicAuthenticationServiceImpl;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc.AuthenticationServerServiceImplBase;
import pt.ulisboa.ist.sirs.authenticationserver.domain.AuthenticationServerState;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;

import java.time.OffsetDateTime;

public final class AuthenticationServerImpl extends AuthenticationServerServiceImplBase {
  private abstract static class AuthenticationServiceImpl extends AbstractCryptographicAuthenticationServiceImpl implements BindableService {
    @Override
    public abstract ServerServiceDefinition bindService();
  }
  private final boolean debug;
  private final AuthenticationServerState state;
  private final AuthenticationServerCryptographicManager crypto;
  public final BindableService service;

  public AuthenticationServerImpl(AuthenticationServerState state, AuthenticationServerCryptographicManager crypto,
      boolean debug) {
    final AuthenticationServerImpl serverImpl = this;
    this.debug = debug;
    this.state = state;
    this.crypto = crypto;
    this.service = new AuthenticationServiceImpl() {
      @Override
      public ServerServiceDefinition bindService() {
        return super.bindService(crypto, serverImpl);
      }
    };
  }

  private boolean isDebug() {
    return debug;
  }

  @Override
  public void diffieHellmanExchange(
    DiffieHellmanExchangeRequest request, StreamObserver<DiffieHellmanExchangeResponse> responseObserver
  ) {
    try {
      String client = crypto.getClientHash(AuthenticationServerServiceGrpc.getDiffieHellmanExchangeMethod().getFullMethodName());

      DiffieHellmanExchangeParameters params = state.diffieHellmanExchange(
        request.getClientPublic().toByteArray(), client
      );

      responseObserver.onNext(DiffieHellmanExchangeResponse.newBuilder()
        .setServerPublic(ByteString.copyFrom(params.publicKey()))
        .setParameters(ByteString.copyFrom(params.parameters()))
        .build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void authenticate(
    AuthenticateRequest request, StreamObserver<AuthenticateResponse> responseObserver
  ) {
    try {
      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: deserialize and parse request");
      String client = crypto.getClientHash(AuthenticationServerServiceGrpc.getAuthenticateMethod().getFullMethodName());
      String source = request.getSource();
      OffsetDateTime timestamp = OffsetDateTime.parse(request.getTimeStamp());

      AuthTicket ticket = state.authenticate(source, client, timestamp);

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: serialize and send response");
      responseObserver.onNext(
        AuthenticateResponse.newBuilder()
         .setAddress(ticket.address())
        .setPort(ticket.port())
        .setTimeStamp(ticket.timeStamp().toString())
        .setSessionKey(ByteString.copyFrom(ticket.sessionKey()))
        .setSessionIV(ByteString.copyFrom(ticket.sessionIV()))
        .setQualifier(ticket.qualifier())
        .setTicket(ByteString.copyFrom(ticket.ticket()))
      .build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(Status.ABORTED.withDescription(e.getMessage()).asRuntimeException());
    }
  }
}
