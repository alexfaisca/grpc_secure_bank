package pt.ulisboa.ist.sirs.authenticationserver;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.dto.DiffieHellmanExchangeParameters;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServerServiceGrpc.NamingServerServiceImplBase;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.TamperedMessageException;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

  @Override
  public void initiateEncryptedKeyExchange(InitiateEncryptedKeyExchangeRequest request, StreamObserver<InitiateEncryptedKeyExchangeResponse> responseObserver) {
    try {
      responseObserver.onNext(InitiateEncryptedKeyExchangeResponse.newBuilder().setServerCert(
      ByteString.copyFrom(
        Utils.readBytesFromFile(Base.CryptographicCore.getCertPath())
      )).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void encryptedKeyExchange(EncryptedKeyExchangeRequest request, StreamObserver<EncryptedKeyExchangeResponse> responseObserver) {
    try {
      String client = crypto.getEKEClientHash();
      CertificateFactory certGen = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certGen.generateCertificate(
        new ByteArrayInputStream(request.getClientCert().toByteArray())
      );
      cert.checkValidity();
      Utils.writeBytesToFile(cert.getPublicKey().getEncoded(), crypto.buildPublicKeyPath(client));
      DiffieHellmanExchangeParameters parameters = state.diffieHellmanExchange(Operations.decryptDataAsymmetric(
        Base.readPrivateKey(crypto.getPrivateKeyPath()),
        request.getClientParams().toByteArray())
      );

      int random = Base.generateRandom(Integer.MAX_VALUE).intValue();
      crypto.setNonce(random);
      responseObserver.onNext(EncryptedKeyExchangeResponse.newBuilder().setServerParams(
        ByteString.copyFrom(Operations.encryptDataAsymmetric(
          Base.readPublicKey(crypto.buildPublicKeyPath(client)),
          Utils.serializeJson(Json.createObjectBuilder()
            .add("serverPublic", Utils.byteToHex(parameters.publicKey()))
            .add("parameters", Utils.byteToHex(parameters.parameters()))
            .build()
      )))).setServerChallenge(
        ByteString.copyFrom(Operations.encryptData(
          Base.readSecretKey(crypto.buildSymmetricKeyPath(client)),
          Base.intToByteArray(random),
          Base.readIv(crypto.buildIVPath(client))
      ))).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }

  @Override
  public void encryptedKeyExchangeChallenge(EncryptedKeyExchangeChallengeRequest request, StreamObserver<EncryptedKeyExchangeChallengeResponse> responseObserver) {
    try {
      String client = crypto.getEKEChallengeClientHash();
      JsonObject finJson = Utils.deserializeJson(Operations.decryptData(
        Base.readSecretKey(crypto.buildPublicKeyPath(client)),
        request.getFinalizeClient().toByteArray(),
        Base.readIv(crypto.buildIVPath(client))
      ));

      if (!crypto.checkNonce(finJson.getInt("serverChallenge")))
        throw new TamperedMessageException();

      responseObserver.onNext(EncryptedKeyExchangeChallengeResponse.newBuilder().setFinalizeServer(
        ByteString.copyFrom(Operations.encryptData(
          Base.readSecretKey(crypto.buildSymmetricKeyPath(client)),
          Base.intToByteArray(finJson.getInt("clientChallenge") + 1),
          Base.readIv(crypto.buildIVPath(client))
      ))).build());
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(new RuntimeException(e.getMessage()));
    }
  }
}
