package pt.ulisboa.ist.sirs.userclient;

import pt.ulisboa.ist.sirs.userclient.grpc.UserService;
import pt.ulisboa.ist.sirs.userclient.tools.SecureDocument;

public class UserClientMain {
    public static void main(String[] args) throws Exception {

        if (
            System.getenv("server-address") == null ||
            System.getenv("server-port") == null ||
            System.getenv("authentication-server-address") == null ||
            System.getenv("authentication-server-port") == null ||
            System.getenv("path-iv") == null ||
            System.getenv("path-secret-key") == null ||
            System.getenv("path-public-key") == null ||
            System.getenv("path-private-key") == null ||
            System.getenv("path-server-cert") == null
        )
            throw new Exception("""
                Bad program usage. Please provide the following environment variables
                    1. <server-address>
                    2. <server-port>
                    3. <authentication-server-address>
                    4. <authentication-server-port>
                    5. <path-iv>
                    6. <path-secret-key>
                    7. <path-public-key>
                    8. <path-private-key>
                    9. <path-server-cert>
                """
            );

        final boolean debug = System.getProperty("debug") != null;

        System.out.println(UserClientMain.class.getSimpleName());
        UserService userService = new UserService.UserServiceBuilder(
                System.getenv("server-address"),
                Integer.parseInt(System.getenv("server-port")),
                System.getenv("authentication-server-address"),
                Integer.parseInt(System.getenv("authentication-server-port")),
                System.getenv("path-iv"),
                System.getenv("path-secret-key"),
                System.getenv("path-public-key"),
                System.getenv("path-private-key"),
                System.getenv("path-server-cert"),
                debug
        ).build();

        CommandParser parser = new CommandParser(
            userService,
            new SecureDocument(
                    System.getenv("path-iv"),
                    System.getenv("path-secret-key"),
                    System.getenv("path-public-key"),
                    System.getenv("path-private-key")
            )
        );

        parser.parseInput();
        if (debug) System.out.println("UserClient: Shutting down");
    }
}