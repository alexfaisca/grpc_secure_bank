package pt.ulisboa.ist.sirs.userclient.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;
import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.utils.*;

public abstract class ClientCryptographicCore implements Base.CryptographicCore {

  protected static <RespT> boolean check(
    RespT ignore1, RespT ignore2, String ignore3, String ignore4
  ) throws Exception {
    throw new Exception("No such request");
  }

  protected static <RespT> RespT decrypt(RespT ignore1, String ignore2, String ignore3) throws Exception {
    throw new Exception("No such request");
  }

  protected static <ReqT> ReqT encrypt(ReqT ignore1, String ignore2, String ignore3, String ignore4) throws Exception {
    throw new Exception("No such response");
  }

  public boolean checkByteArray(
    byte[] message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath), Base.readIv(ivPath)
    );
  }

  public static byte[] decryptByteArray(byte[] message, String secretKeyPath, String ivPath) throws Exception {
    return Decrypter.decryptByteArray(message, Base.readSecretKey(secretKeyPath), Base.readIv(ivPath));
  }

  protected static byte[] encryptByteArray(
          byte[] message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return Encrypter.encrypt(
            message, Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    );
  }

  protected static boolean check(
    AuthenticateResponse message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message.getResponse().toByteArray(),
      Base.readSecretKey(secretKeyPath),
      Base.readPublicKey(publicKeyPath),
      Base.readIv(ivPath)
    );
  }

  protected static boolean check(
    StillAliveResponse message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message.getResponse().toByteArray(),
      Base.readSecretKey(secretKeyPath),
      Base.readPublicKey(publicKeyPath),
      Base.readIv(ivPath)
    );
  }

  protected static AuthenticateResponse decrypt(
    AuthenticateResponse message, String secretKeyPath, String ivPath
  ) throws Exception {
    return AuthenticateResponse.newBuilder().setResponse(
      ByteString.copyFrom(Utils.serializeJson(
        Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath), Base.readIv(ivPath))))
    ).build();
  }

  protected static StillAliveResponse decrypt(
    StillAliveResponse message, String secretKeyPath, String ivPath
  ) throws Exception {
    return StillAliveResponse.newBuilder().setResponse(
      ByteString.copyFrom(Utils.serializeJson(
        Decrypter.decrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath), Base.readIv(ivPath))))
    ).build();
  }

  protected static StillAliveRequest encrypt(
    StillAliveRequest message,
    String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return StillAliveRequest.newBuilder().setRequest(
      ByteString.copyFrom(
        Encrypter.encrypt(
          message.getRequest().toByteArray(),
          Base.readSecretKey(secretKeyPath),
          Base.readPrivateKey(privateKeyPath),
          Base.readIv(ivPath)))
    ).build();
  }
}
