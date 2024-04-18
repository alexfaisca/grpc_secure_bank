package pt.tecnico.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.tecnico.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.tecnico.sirs.contract.authenticationserver.AuthenticationServerServiceGrpc.AuthenticationServerServiceImplBase;
import pt.tecnico.sirs.authenticationserver.domain.AuthenticationServerState;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.json.*;
import java.time.OffsetDateTime;

public final class AuthenticationServerImpl extends AuthenticationServerServiceImplBase {
  private final boolean debug;
  private final AuthenticationServerState state;

  public AuthenticationServerImpl(AuthenticationServerState state, boolean debug) {
    this.debug = debug;
    this.state = state;
  }

  private boolean isDebug() {
    return debug;
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
      byte[] ticket = state.authenticate(source, target, timestamp);

      if (isDebug())
        System.out.println("\tAuthenticationServerImpl: serialize and send response");
      responseObserver.onNext(AuthenticateResponse.newBuilder().setResponse(ByteString.copyFrom(ticket)).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
