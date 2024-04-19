package pt.ulisboa.ist.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc.AuthenticationServerServiceImplBase;
import pt.ulisboa.ist.sirs.authenticationserver.domain.AuthenticationServerState;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.AuthenticationServerCryptographicInterceptor;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.json.*;
import java.time.OffsetDateTime;

public final class AuthenticationServerImpl extends AuthenticationServerServiceImplBase {
  private final boolean debug;
  private final AuthenticationServerState state;
  private final AuthenticationServerCryptographicInterceptor crypto;

  public AuthenticationServerImpl(AuthenticationServerState state, AuthenticationServerCryptographicInterceptor crypto,
      boolean debug) {
    this.debug = debug;
    this.state = state;
    this.crypto = crypto;
  }

  private boolean isDebug() {
    return debug;
  }

  @Override
  public void diffieHellmanExchange(DiffieHellmanExchangeRequest request,
      StreamObserver<DiffieHellmanExchangeResponse> responseObserver) {
    try {
      String client = crypto.popFromQueue(DiffieHellmanExchangeRequest.class);
      DiffieHellmanExchangeParameters params = state.diffieHellmanExchange(request.getClientPublic().toByteArray(),
          client, OffsetDateTime.parse(request.getTimestamp()));

      responseObserver.onNext(DiffieHellmanExchangeResponse.newBuilder()
          .setServerPublic(ByteString.copyFrom(params.publicKey()))
          .setParameters(ByteString.copyFrom(params.parameters()))
          .build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }

  @Override
  public void authenticate(AuthenticateRequest request, StreamObserver<AuthenticateResponse> responseObserver) {
    try {
      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: deserialize and parse request");
      JsonObject requestJson = Utils.deserializeJson(request.getRequest().toByteArray());
      String source = requestJson.getString("source");
      String target = requestJson.getString("target");
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: delegate");
      byte[] ticket = state.authenticate(source, target, crypto.popFromQueue(AuthenticateRequest.class), timestamp);

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: serialize and send response");
      responseObserver.onNext(AuthenticateResponse.newBuilder().setResponse(ByteString.copyFrom(ticket)).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
