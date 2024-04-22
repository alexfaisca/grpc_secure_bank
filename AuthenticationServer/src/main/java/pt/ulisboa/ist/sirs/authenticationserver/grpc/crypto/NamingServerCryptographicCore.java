package pt.ulisboa.ist.sirs.authenticationserver.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.contract.namingserver.NamingServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;

public class NamingServerCryptographicCore implements Base.CryptographicCore {
  protected static <ReqT> ReqT decrypt(ReqT ignore1, String ignore2, String ignore3) throws Exception {
    throw new Exception("No such request");
  }

  protected static <RespT> RespT encrypt(RespT ignore1, String ignore2, String ignore3) throws Exception {
    throw new Exception("No such response");
  }

  protected static RegisterRequest decrypt(
    RegisterRequest message, String secretKeyPath, String ivPath
  ) throws Exception {
    return RegisterRequest.newBuilder().setRequest(
      ByteString.copyFrom(
        Operations.decryptData(
          Base.readSecretKey(secretKeyPath),
          message.getRequest().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }

  protected static RegisterResponse encrypt(
          RegisterResponse message, String secretKeyPath, String ivPath
  ) throws Exception {
    return RegisterResponse.newBuilder().setResponse(
      ByteString.copyFrom(
        Operations.encryptData(
          Base.readSecretKey(secretKeyPath),
          message.getResponse().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }

  protected static DeleteRequest decrypt(
          DeleteRequest message, String secretKeyPath, String ivPath
  ) throws Exception {
    return DeleteRequest.newBuilder().setRequest(
      ByteString.copyFrom(
        Operations.decryptData(
          Base.readSecretKey(secretKeyPath),
          message.getRequest().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }

  protected static DeleteResponse encrypt(
          DeleteResponse message, String secretKeyPath, String ivPath
  ) throws Exception {
    return DeleteResponse.newBuilder().setResponse(
      ByteString.copyFrom(
        Operations.encryptData(
          Base.readSecretKey(secretKeyPath),
          message.getResponse().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }

  protected static LookupRequest decrypt(
          LookupRequest message, String secretKeyPath, String ivPath
  ) throws Exception {
    return LookupRequest.newBuilder().setRequest(
      ByteString.copyFrom(
        Operations.decryptData(
          Base.readSecretKey(secretKeyPath),
          message.getRequest().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }

  protected static LookupResponse encrypt(
          LookupResponse message, String secretKeyPath, String ivPath
  ) throws Exception {
    return LookupResponse.newBuilder().setResponse(
      ByteString.copyFrom(
        Operations.encryptData(
          Base.readSecretKey(secretKeyPath),
          message.getResponse().toByteArray(),
          Base.readIv(ivPath))
    )).build();
  }
}