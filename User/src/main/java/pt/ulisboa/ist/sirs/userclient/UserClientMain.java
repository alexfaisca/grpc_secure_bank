package pt.ulisboa.ist.sirs.userclient;

import pt.ulisboa.ist.sirs.userclient.grpc.UserService;
import pt.ulisboa.ist.sirs.userclient.grpc.crypto.BankingClientCryptographicManager;
import pt.ulisboa.ist.sirs.userclient.tools.SecureDocument;
import pt.ulisboa.ist.sirs.utils.Utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class UserClientMain {
  public static void main(String[] args) throws Exception {

    if (
      System.getenv("server-address") == null ||
      System.getenv("server-port") == null ||
      System.getenv("authentication-server-address") == null ||
      System.getenv("authentication-server-port") == null ||
      System.getenv("path-server-cert") == null
    )
      throw new Exception("""
        Bad program usage. Please provide the following environment variables
            1. <server-address>
            2. <server-port>
            3. <authentication-server-address>
            4. <authentication-server-port>
            5. <path-server-cert>
        """
      );

    final boolean debug = System.getProperty("debug") != null;
    final BankingClientCryptographicManager crypto = new BankingClientCryptographicManager();
    BankingClientCryptographicManager.initializeCryptoCache();
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(4096);
    KeyPair kp = kpg.generateKeyPair();
    Utils.writeBytesToFile(
      kp.getPublic().getEncoded(),
      BankingClientCryptographicManager.buildSelfPublicKeyPath()
    );
    Utils.writeBytesToFile(
      kp.getPrivate().getEncoded(),
      BankingClientCryptographicManager.buildSelfPrivateKeyPath()
    );

    System.out.println(UserClientMain.class.getSimpleName());
    UserService userService = new UserService.UserServiceBuilder(
      System.getenv("server-address"),
      Integer.parseInt(System.getenv("server-port")),
      System.getenv("authentication-server-address"),
      Integer.parseInt(System.getenv("authentication-server-port")),
      System.getenv("path-server-cert"),
      crypto,
      debug
    ).build();

    CommandParser parser = new CommandParser(
      userService,
      new SecureDocument()
    );

    parser.parseInput();
    if (debug) System.out.println("UserClient: Shutting down");
  }
}