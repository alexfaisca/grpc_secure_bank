package pt.ulisboa.ist.sirs.authenticationserver;

import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc.NamingServerServiceImplBase;

public final class NamingServerImpl extends NamingServerServiceImplBase {
  private final boolean debug;
  private final NamingServerState state;
  private final NamingServerCryptographicManager crypto;
  public NamingServerImpl(NamingServerState state, NamingServerCryptographicManager crypto, boolean debug) {
    super();
    this.debug = debug;
    this.state = state;
    this.crypto = crypto;
  }
}
