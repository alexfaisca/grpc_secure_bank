package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;

import java.io.File;

public class NamingServerCryptographicManager extends NamingServerCryptographicCore {
    private final ServerCryptographicInterceptor crypto;

    public NamingServerCryptographicManager(ServerCryptographicInterceptor crypto) {
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

    public <P> P encrypt(P object) throws Exception {
        return encrypt(object, "", "");
    }

    public <P> P decrypt(P object) throws Exception {
        return decrypt(object, "", "");
    }

    public RegisterResponse encrypt(RegisterResponse object) throws Exception {
        crypto.popFromQueue(RegisterRequest.class);
        return object;
    }

    public RegisterRequest decrypt(RegisterRequest object) throws Exception {
        return object;
    }

    public LookupResponse encrypt(LookupResponse object) throws Exception {
        String client = crypto.popFromQueue(LookupRequest.class);
        return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }

    public LookupRequest decrypt(LookupRequest object) throws Exception {
        String client = crypto.getFromQueue(LookupRequest.class);
        return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }

    public DeleteResponse encrypt(DeleteResponse object) throws Exception {
        String client = crypto.popFromQueue(DeleteRequest.class);
        return encrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }

    public DeleteRequest decrypt(DeleteRequest object) throws Exception {
        String client = crypto.getFromQueue(DeleteRequest.class);
        return decrypt(object, buildSymmetricKeyPath(client), buildIVPath(client));
    }
}
