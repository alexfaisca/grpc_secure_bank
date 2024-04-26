package pt.ulisboa.ist.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.BindableService;
import io.grpc.ServerServiceDefinition;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.domain.utils.ServiceTypesConverter;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.dto.KeyBundle;
import pt.ulisboa.ist.sirs.authenticationserver.dto.TargetServer;
import pt.ulisboa.ist.sirs.authenticationserver.exceptions.ServiceHasNoRegisteredServersException;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AbstractCryptographicNamingServiceImpl;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc.NamingServerServiceImplBase;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import java.util.List;

public final class NamingServerImpl extends NamingServerServiceImplBase {
  private abstract static class NamingServiceImpl extends AbstractCryptographicNamingServiceImpl implements BindableService {
    @Override
    public abstract ServerServiceDefinition bindService();
  }
  private final boolean debug;
  private final NamingServerState state;
  private final NamingServerCryptographicManager crypto;
  public final  BindableService service;
  public NamingServerImpl(NamingServerState state, NamingServerCryptographicManager crypto, boolean debug) {
    super();
    final NamingServerImpl serverImpl = this;
    this.debug = debug;
    this.state = state;
    this.crypto = crypto;
    this.service = new NamingServiceImpl() {
      @Override
      public ServerServiceDefinition bindService() {
        return super.bindService(crypto, serverImpl);
      }
    };
  }

  public BindableService getService() {
    return service;
  }

  @Override
  public void initiateEncryptedKeyExchange(
    Ack request, StreamObserver<InitiateEncryptedKeyExchangeResponse> responseObserver
  ) {
    try {
      responseObserver.onNext(InitiateEncryptedKeyExchangeResponse.newBuilder().setServerCert(
      ByteString.copyFrom(
        Utils.readBytesFromFile(Base.CryptographicCore.getCertPath())
      )).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void encryptedKeyExchange(
    EncryptedKeyExchangeRequest request, StreamObserver<EncryptedKeyExchangeResponse> responseObserver
  ) {
    try {
      String client = crypto.getClientHash(NamingServerServiceGrpc.getEncryptedKeyExchangeMethod().getFullMethodName());

      crypto.validateSession(request.getClientCert().toByteArray());
      KeyBundle keyBundle = crypto.getEphemeralBundle(request.getClientOps().toByteArray());

      DiffieHellmanExchangeParameters parameters = state.diffieHellmanExchange(
        crypto.decryptWithEphemeral(keyBundle, request.getClientParams().toByteArray()), client
      );

      responseObserver.onNext(EncryptedKeyExchangeResponse.newBuilder().setServerParams(
        ByteString.copyFrom((crypto.encryptWithEphemeral(
          keyBundle, crypto.bundleEKEParams(parameters.parameters(), parameters.publicKey())
      )))).setServerChallenge(
        ByteString.copyFrom(crypto.encryptWithSession(Utils.longToByteArray(crypto.initializeNonce()), client))
      ).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void encryptedKeyExchangeChallenge(
    EncryptedKeyExchangeChallengeRequest request, StreamObserver<EncryptedKeyExchangeChallengeResponse> responseObserver
  ) {
    try {
      if (!crypto.checkNonce(request.getServerChallenge() - 1))
        throw new TamperedMessageException();

      responseObserver.onNext(
        EncryptedKeyExchangeChallengeResponse.newBuilder().setClientChallenge(request.getClientChallenge() +1).build()
      );
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void register(RegisterRequest request, StreamObserver<Ack> responseObserver) {
    try {
      String client = crypto.getClientHash(NamingServerServiceGrpc.getRegisterMethod().getFullMethodName());
      if (crypto.checkServerCache(client))
        throw new RuntimeException("Please perform eke first.");

      state.register(
        ServiceTypesConverter.convert(request.getService()),
        client,
        request.getAddress(),
        request.getPort(),
        request.getQualifier()
      );

      responseObserver.onNext(Ack.getDefaultInstance());
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void lookup(LookupRequest request, StreamObserver<LookupResponse> responseObserver) {
    try {
      String client = crypto.getClientHash(NamingServerServiceGrpc.getDeleteMethod().getFullMethodName());
      if (crypto.checkServerCache(client))
        throw new RuntimeException("Please perform eke first.");

      List<TargetServer> servers = state.lookupServiceServers(
        ServiceTypesConverter.convert(request.getService())
      );
      if (servers.isEmpty())
        throw new ServiceHasNoRegisteredServersException(ServiceTypesConverter.convert(request.getService()).name());

      responseObserver.onNext(LookupResponse.newBuilder().addAllServers(
        servers.stream().map(s -> LookupResponse.ServerEntryResponse.newBuilder()
          .setAddress(s.address())
          .setPort(s.port())
          .setQualifier(s.qualifier())
          .build()).toList()
      ).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void delete(DeleteRequest request, StreamObserver<Ack> responseObserver) {
    try {
      state.delete(
        ServiceTypesConverter.convert(request.getService()),
        request.getQualifier()
      );
      responseObserver.onNext(Ack.getDefaultInstance());
      responseObserver.onCompleted();
    } catch (Exception e) {
      if (debug) System.out.println(e.getMessage());
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }
}
