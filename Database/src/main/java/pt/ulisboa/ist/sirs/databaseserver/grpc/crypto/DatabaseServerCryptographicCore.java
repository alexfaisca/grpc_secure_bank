package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import com.google.protobuf.ByteString;
import pt.ulisboa.ist.sirs.contract.databaseserver.DatabaseServer.*;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.utils.Utils;

public class DatabaseServerCryptographicCore implements Base.CryptographicCore {

  public boolean checkByteArray(
    byte[] message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath), Base.readIv(ivPath)
    );
  }

  public static byte[] decryptByteArray(
    byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
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
    StillAliveRequest message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message.getRequest().toByteArray(),
      Base.readSecretKey(secretKeyPath),
      Base.readPublicKey(publicKeyPath),
      Base.readIv(ivPath)
    );
  }

  protected static AuthenticateRequest decrypt(
    AuthenticateRequest message, String secretKeyPath, String ivPath
  ) throws Exception {
    return AuthenticateRequest.newBuilder().setRequest(
      ByteString.copyFrom(Operations.decryptData(
        Base.readSecretKey(secretKeyPath),
        message.getRequest().toByteArray(),
        Base.readIv(ivPath)
    ))).build();
  }

  protected static AuthenticateResponse encrypt(
    AuthenticateResponse message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return AuthenticateResponse.newBuilder().setResponse(
      ByteString.copyFrom(Encrypter.encrypt(
        message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    ))).build();
  }

  protected static StillAliveResponse encrypt(
    StillAliveResponse message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return StillAliveResponse.newBuilder().setResponse(
      ByteString.copyFrom(
        Encrypter.encrypt(message.getResponse().toByteArray(), Base.readSecretKey(secretKeyPath),
          Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    ))).build();
  }

  protected static StillAliveRequest decrypt(
    StillAliveRequest message, String secretKeyPath, String ivPath
  ) throws Exception {
    return StillAliveRequest.newBuilder().setRequest(
      ByteString.copyFrom(Utils.serializeJson(Decrypter.decrypt(
        message.getRequest().toByteArray(), Base.readSecretKey(secretKeyPath), Base.readIv(ivPath)
    )))).build();
  }
}
