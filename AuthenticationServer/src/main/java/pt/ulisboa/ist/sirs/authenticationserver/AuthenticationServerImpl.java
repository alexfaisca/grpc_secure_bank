package pt.ulisboa.ist.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc.AuthenticationServerServiceImplBase;
import pt.ulisboa.ist.sirs.authenticationserver.domain.AuthenticationServerState;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.json.*;
import java.time.OffsetDateTime;

public final class AuthenticationServerImpl extends AuthenticationServerServiceImplBase {
  private final boolean debug;
  private final AuthenticationServerState state;
  private final AuthenticationServerCryptographicManager crypto;

  public AuthenticationServerImpl(AuthenticationServerState state, AuthenticationServerCryptographicManager crypto,
      boolean debug) {
    this.debug = debug;
    this.state = state;
    this.crypto = crypto;
  }

  private boolean isDebug() {
    return debug;
  }

  @Override
  public void diffieHellmanExchange(
    DiffieHellmanExchangeRequest request, StreamObserver<DiffieHellmanExchangeResponse> responseObserver
  ) {
    try {
      request = crypto.decrypt(request);

      DiffieHellmanExchangeParameters params = state.diffieHellmanExchange(
        request.getClientPublic().toByteArray()
      );

      responseObserver.onNext(crypto.encrypt(DiffieHellmanExchangeResponse.newBuilder()
        .setServerPublic(ByteString.copyFrom(params.publicKey()))
        .setParameters(ByteString.copyFrom(params.parameters()))
        .build()));
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }

  @Override
  public void authenticate(
    AuthenticateRequest request, StreamObserver<AuthenticateResponse> responseObserver
  ) {
    try {
      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: deserialize and parse request");
      String client = crypto.getASClientHash();
      JsonObject requestJson = Utils.deserializeJson(crypto.decrypt(request).getRequest().toByteArray());
      String source = requestJson.getString("source");
      String target = requestJson.getString("target");
      OffsetDateTime timestamp = OffsetDateTime.parse(requestJson.getString("timestampString"));

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: delegate");
      byte[] ticket = state.authenticate(source, target, client, timestamp);

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: serialize and send response");
      responseObserver.onNext(crypto.encrypt(
        AuthenticateResponse.newBuilder().setResponse(ByteString.copyFrom(ticket)).build()
      ));
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
