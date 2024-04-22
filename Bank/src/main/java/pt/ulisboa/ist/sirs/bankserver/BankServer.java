package pt.ulisboa.ist.sirs.bankserver;

import io.grpc.*;
import pt.ulisboa.ist.sirs.bankserver.domain.BankState;
import pt.ulisboa.ist.sirs.bankserver.grpc.crypto.AuthenticationClientCryptographicManager;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.io.*;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

public class BankServer {
  private final boolean debug;
  private final BankState state;
  private final Server server;

  public BankServer(List<String> args, boolean debug) throws Exception {
    this.debug = debug;

    final String bankAddress = args.get(2);
    final int bankPort = Integer.parseInt(args.get(3));
    final String databaseAddress = args.get(4);
    final int databasePort = Integer.parseInt(args.get(5));
    final String authenticationServerAddress = args.get(6);
    final int authenticationServerPort = Integer.parseInt(args.get(7));

    this.state = new BankState.BankStateBuilder(
        args.get(0), args.get(1), bankAddress, bankPort, databaseAddress, databasePort, authenticationServerAddress,
        authenticationServerPort, args.get(8), args.get(9), args.get(10), new AuthenticationClientCryptographicManager(), debug).build();

    final BindableService bankingService = new BankServerImpl(state, debug);

    TlsServerCredentials.Builder tlsBuilder = TlsServerCredentials.newBuilder()
        .keyManager(new File(args.get(9)), new File(args.get(10)));
    this.server = Grpc.newServerBuilderForPort(bankPort, tlsBuilder.build()).addService(bankingService)
        .build();
  }

  private void serverStartup() throws IOException {
    if (debug)
      System.out.println("Server: Starting up '" + state.getBankingService() + "''s '" + state.getServerName()
          + "' server at " + state.getServerAddress() + ":" + state.getServerPort() + ".");
    state.register();
    server.start();
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
      System.out.println("Server: Deleting '" + state.getBankingService() + "''s '" + state.getServerName()
          + "' server at " + state.getServerAddress() + ".");
    state.delete();
    System.out.println("Shutting down.");
    if (server.awaitTermination(1, TimeUnit.SECONDS))
      server.shutdownNow();
  }

  private void blockUntilShutDown() throws InterruptedException {
    System.out
        .println("Press ENTER to delete '" + state.getBankingService() + "''s '" + state.getServerName() + "' server.");
    try (Scanner scan = new Scanner(System.in)) {
      scan.nextLine();
    }
    serverShutdown();
  }

  public static void main(String[] args) throws Exception {
    System.out.println("BlingBank Server");
    final boolean debug = true;

    if (System.getenv("service-name") == null ||
        System.getenv("server-name") == null ||
        System.getenv("server-address") == null ||
        System.getenv("server-port") == null ||
        System.getenv("database-address") == null ||
        System.getenv("database-port") == null ||
        System.getenv("authentication-server-address") == null ||
        System.getenv("authentication-server-port") == null ||
        System.getenv("path-server-trust-chain") == null ||
        System.getenv("path-server-cert") == null ||
        System.getenv("path-server-key") == null)
      throw new Exception("""
          Bad program usage. Please provide the following environment variables
              1.  <service-name>
              2.  <server-name>
              3.  <server-address>
              4.  <server-port>
              5.  <database-address>
              6.  <database-port>
              7.  <authentication-server-address>
              8.  <authentication-server-port>
              9.  <path-server-trust-chain>
              10. <path-server-cert>
              11. <path-server-key>
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

      BankServer server = new BankServer(
        List.of(
          System.getenv("service-name"),
          System.getenv("server-name"),
          System.getenv("server-address"),
          System.getenv("server-port"),
          System.getenv("database-address"),
          System.getenv("database-port"),
          System.getenv("authentication-server-address"),
          System.getenv("authentication-server-port"),
          System.getenv("path-server-trust-chain"),
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
