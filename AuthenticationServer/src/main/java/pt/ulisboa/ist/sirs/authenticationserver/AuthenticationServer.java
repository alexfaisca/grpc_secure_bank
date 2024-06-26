package pt.ulisboa.ist.sirs.authenticationserver;

import io.grpc.*;
import pt.ulisboa.ist.sirs.authenticationserver.domain.AuthenticationServerState;
import pt.ulisboa.ist.sirs.authenticationserver.domain.NamingServerState;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.NamingServerCryptographicManager;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.ServerCryptographicInterceptor;
import pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto.AuthenticationServerCryptographicManager;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.*;
import java.security.KeyFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Scanner;

public class AuthenticationServer {
  private final boolean debug;
  private final AuthenticationServerState state;
  private final Server server;

  public AuthenticationServer(List<String> args, boolean debug) throws IOException {
    this.debug = debug;

    final String authenticationServerAddress = args.get(2);
    final int authenticationServerPort = Integer.parseInt(args.get(3));
    final ServerCryptographicInterceptor authInterceptor = new ServerCryptographicInterceptor();
    final ServerCryptographicInterceptor namingInterceptor = new ServerCryptographicInterceptor();
    final AuthenticationServerCryptographicManager crypto = new AuthenticationServerCryptographicManager(authInterceptor);
    final NamingServerCryptographicManager namingCrypto = new NamingServerCryptographicManager(namingInterceptor);
    NamingServerState namingState = new NamingServerState.NamingServerStateBuilder(
            namingCrypto, args.get(0), args.get(1), authenticationServerAddress, authenticationServerPort, debug
    ).build();
    this.state = new AuthenticationServerState.AuthenticationServerStateBuilder(
      crypto, namingState, args.get(0), args.get(1), authenticationServerAddress, authenticationServerPort, debug
    ).build();

    final BindableService AuthenticationServerService = new AuthenticationServerImpl(state, crypto, debug).getService();
    final BindableService NamingServerService = new NamingServerImpl(namingState, namingCrypto, debug).getService();

    ServerCredentials tlsBuilder = TlsServerCredentials.create(new File(args.get(4)), new File(args.get(5)));
    this.server = Grpc.newServerBuilderForPort(authenticationServerPort, tlsBuilder)
        .addService(ServerInterceptors.intercept(AuthenticationServerService, authInterceptor))
        .addService(ServerInterceptors.intercept(NamingServerService, namingInterceptor))
        .build();
  }

  private void serverStartup() throws IOException {
    if (debug)
      System.out.println("Server: Starting up '" + state.getAuthenticationServerService() + "''s '"
          + state.getServerName() + "' server at " + state.getServerAddress() + ":" + state.getServerPort() + ".");
    server.start();
    state.register();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      try {
        serverShutdown();
      } catch (InterruptedException e) {
        System.out.println(e.getMessage());
      }
    }));
  }

  private void serverShutdown() throws InterruptedException {
    if (debug)
      System.out.println("Server: Deleting '" + state.getAuthenticationServerService() + "''s '" + state.getServerName()
          + "' server at " + state.getServerAddress() + ".");
    System.out.println("Shutting down.");
    state.delete();
    server.shutdownNow();
  }

  private void blockUntilShutDown() throws InterruptedException {
    System.out.println("Press ENTER to delete '" + state.getAuthenticationServerService() + "''s '"
        + state.getServerName() + "' server.");
    try (Scanner scan = new Scanner(System.in)) {
      scan.nextLine();
    }
    serverShutdown();
  }

  public static void main(String[] args) throws Exception {
    System.out.println("Authentication Server");
    final boolean debug = true;

    if (System.getenv("service-name") == null ||
        System.getenv("server-name") == null ||
        System.getenv("server-address") == null ||
        System.getenv("server-port") == null ||
        System.getenv("path-server-cert") == null ||
        System.getenv("path-server-key") == null)
      throw new Exception("""
          Bad program usage. Please provide the following environment variables
              1.  <service-name>
              2.  <server-name>
              3.  <server-address>
              4.  <serverP-port>
              5.  <path-server-cert>
              6.  <path-server-key>
              ...
          """);

    try (FileInputStream certFile = new FileInputStream(System.getenv("path-server-cert"))) {
      CertificateFactory certGen = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) certGen.generateCertificate(certFile);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Utils.readBytesFromPemFile(System.getenv("path-server-key")));
      Base.CryptographicCore.initializeSelfDirectory();
      Utils.writeBytesToFile(cert.getPublicKey().getEncoded(), Base.CryptographicCore.getPublicKeyPath());
      Utils.writeBytesToFile(keyFactory.generatePrivate(keySpec).getEncoded(), Base.CryptographicCore.getPrivateKeyPath());

      AuthenticationServer server = new AuthenticationServer(
        List.of(
          System.getenv("service-name"),
          System.getenv("server-name"),
          System.getenv("server-address"),
          System.getenv("server-port"),
          System.getenv("path-server-cert"),
          System.getenv("path-server-key")),
          debug
      );

      server.serverStartup();
      server.blockUntilShutDown();
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }
}
