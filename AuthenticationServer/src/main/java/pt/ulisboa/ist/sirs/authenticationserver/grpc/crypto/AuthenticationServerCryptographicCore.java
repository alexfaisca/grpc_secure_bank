package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.contract.authenticationserver.AuthenticationServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;


public class AuthenticationServerCryptographicCore implements Base.CryptographicCore {

    protected static <ReqT> ReqT decrypt(ReqT ignore1, String ignore2, String ignore3) throws Exception {
        throw new Exception("No such request");
    }

    protected static <RespT> RespT encrypt(RespT ignore1, String ignore2, String ignore3) throws Exception {
        throw new Exception("No such response");
    }

    protected static AuthenticateRequest decrypt(
            AuthenticateRequest message, String secretKeyPath, String ivPath
    ) throws Exception {
        return AuthenticateRequest.newBuilder().setRequest(
            ByteString.copyFrom(
                Operations.decryptData(
                    Base.readSecretKey(secretKeyPath),
                    message.getRequest().toByteArray(),
                    Base.readIv(ivPath))
        )).build();
    }

    protected static AuthenticateResponse encrypt(
            AuthenticateResponse message, String secretKeyPath, String ivPath
    ) throws Exception {
        return AuthenticateResponse.newBuilder().setResponse(
            ByteString.copyFrom(
                Operations.encryptData(
                    Base.readSecretKey(secretKeyPath),
                    message.getResponse().toByteArray(),
                    Base.readIv(ivPath))
        )).build();
    }
}
