package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;

import java.io.File;

public class AuthenticationServerCryptographicManager extends AuthenticationServerCryptographicCore {
    private final AuthenticationServerCryptographicInterceptor crypto;

    public AuthenticationServerCryptographicManager(AuthenticationServerCryptographicInterceptor crypto) {
        this.crypto = crypto;
    }

    // For now database symmetricKey and iv are distributed prior to application initialization, hence are static files
    public String getDatabaseSymmetricKeyPath(String database) {
        return "resources/crypto/database/symmetricKey";
    }

    public String getDatabaseIVPath(String database) {
        return "resources/crypto/database/iv";
    }

    public void initializeClientCache(String client) {
        File clientDirectory = new File("resources/crypto/" + client + "/");
        if (!clientDirectory.exists())
            if (!clientDirectory.mkdirs())
                throw new RuntimeException("Could not store client key");
    }

    public String buildSymmetricKeyPath(String client) {
        return "resources/crypto/" + client + "/symmetricKey";
    }

    public String buildIVPath(String client) {
        return "resources/crypto/" + client + "/iv";
    }

    public String getDHClientHash() {
        return crypto.getFromQueue(DiffieHellmanExchangeRequest.class);
    }

    public String getASClientHash() {
        return crypto.getFromQueue(AuthenticateRequest.class);
    }

    public <P> P encrypt(P object) throws Exception {
        return encrypt(object, "", "");
    }

    public <P> P decrypt(P object) throws Exception {
        return decrypt(object, "", "");
    }

    public DiffieHellmanExchangeResponse encrypt(DiffieHellmanExchangeResponse object) throws Exception {
        crypto.popFromQueue(DiffieHellmanExchangeRequest.class);
        return object;
    }

    public DiffieHellmanExchangeRequest decrypt(DiffieHellmanExchangeRequest object) throws Exception {
        return object;
    }

    public AuthenticateResponse encrypt(AuthenticateResponse object) throws Exception {
        String client = crypto.popFromQueue(AuthenticateRequest.class);
        return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }

    public AuthenticateRequest decrypt(AuthenticateRequest object) throws Exception {
        String client = crypto.getFromQueue(AuthenticateRequest.class);
        return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }
}
