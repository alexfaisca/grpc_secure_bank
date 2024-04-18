package pt.tecnico.sirs.databaseserver;

import pt.tecnico.sirs.cryptology.Operations;
import pt.tecnico.sirs.databaseserver.grpc.DatabaseService;
import pt.tecnico.sirs.databaseserver.grpc.crypto.DatabaseServerCryptographicManager;
import pt.tecnico.sirs.databaseserver.repository.DatabaseManager;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import io.grpc.*;

public class DatabaseServer {
  private final boolean debug;
  private final Server server;
  private final DatabaseManager state;

  public DatabaseServer(List<String> args, boolean debug) throws IOException, NoSuchAlgorithmException {
    this.debug = debug;
    final String databaseAddress = args.get(2);
    final int databasePort = Integer.parseInt(args.get(3));

    this.state = new DatabaseManager(
        new DatabaseService(args.get(0), args.get(1), databaseAddress, databasePort, debug));

    // Test add account
    state.createAccount(Collections.singletonList("Alice"), Operations.hash("12345".getBytes()),
        new BigDecimal("10101010101"), OffsetDateTime.now());
    state.createAccount(Collections.singletonList("Bob"), Operations.hash("12345".getBytes()),
        new BigDecimal("9599543"), OffsetDateTime.now());
    // Test order payment
    state.orderPayment("Bob", Operations.hash("12345".getBytes()), LocalDateTime.now(), new BigDecimal("1000"),
        "Last Tuesday's dinner", "Alice", OffsetDateTime.now());

    final DatabaseServerCryptographicManager cryptoCore = new DatabaseServerCryptographicManager(
        args.get(4), args.get(5), args.get(6), args.get(7));

    this.server = Grpc.newServerBuilderForPort(
        databasePort,
        TlsServerCredentials.newBuilder().keyManager(new File(args.get(9)), new File(args.get(10))).build())
        .addService(new DatabaseServerImpl<>(state, cryptoCore, debug)).build();
  }

  private void serverStartup() throws IOException {
    if (debug)
      System.out.println("Database: Starting up '" + state.getService().getServerServiceName() + "''s '"
          + state.getService().getServerName() + "' server at " + state.getService().getServerAddress() + ":"
          + state.getService().getServerPort());
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
      System.out.println("Database: Deleting '" + state.getService().getServerServiceName() + "''s '"
          + state.getService().getServerName() + "' server at " + state.getService().getServerAddress() + ":"
          + state.getService().getServerPort());
    state.shutDown();
    System.out.println("Shutting down.");
    if (server.awaitTermination(1, TimeUnit.SECONDS))
      System.exit(0);
    server.shutdownNow();
  }

  private void blockUntilShutDown() throws InterruptedException {
    System.out.println("Press ENTER to delete '" + state.getService().getServerServiceName() + "''s '"
        + state.getService().getServerName() + "' server.");
    try (Scanner scan = new Scanner(System.in)) {
      scan.nextLine();
    }
    serverShutdown();
  }

  public static void main(String[] args) throws Exception {
    System.out.println("Database Server");
    final boolean debug = true;

    if (System.getenv("service-name") == null ||
        System.getenv("server-name") == null ||
        System.getenv("server-address") == null ||
        System.getenv("server-port") == null ||
        System.getenv("path-iv") == null ||
        System.getenv("path-secret-key") == null ||
        System.getenv("path-public-key") == null ||
        System.getenv("path-private-key") == null ||
        System.getenv("path-server-trust-chain") == null ||
        System.getenv("path-server-cert") == null ||
        System.getenv("path-server-key") == null)
      throw new Exception("""
          Bad program usage. Please provide the following environment variables
              1.  <service-name>
              2.  <server-name>
              3.  <server-address>
              4.  <server-port>
              5.  <path-iv>
              6.  <path-secret-key>
              7.  <path-public-key>
              8.  <path-private-key>
              9.  <path-server-trust-chain>
              10. <path-server-cert>
              11. <path-server-key>
          """);

    try {
      DatabaseServer databaseServer = new DatabaseServer(
          List.of(
              System.getenv("service-name"),
              System.getenv("server-name"),
              System.getenv("server-address"),
              System.getenv("server-port"),
              System.getenv("path-iv"),
              System.getenv("path-secret-key"),
              System.getenv("path-public-key"),
              System.getenv("path-private-key"),
              System.getenv("path-server-trust-chain"),
              System.getenv("path-server-cert"),
              System.getenv("path-server-key")),
          debug);
      databaseServer.serverStartup();
      databaseServer.blockUntilShutDown();
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }
}
