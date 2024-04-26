package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.databaseserver.dto.TicketDto;
import pt.ulisboa.ist.sirs.dto.Ticket;

public class CryptographicCore implements Base.CryptographicCore {
  protected static final String SESSION_DIR = "resources/crypto/session/";
  protected static final String SELF_DIR = "resources/crypto/self/";
  protected static final String AUTH_DIR = "resources/crypto/auth/";

  protected static TicketDto unbundleTicket(byte[] ticket, String secretKeyPath, String ivPath) throws Exception {
    Ticket unbundled = Base.KeyManager.unbundleTicket(Operations.decryptData(
            Base.readSecretKey(secretKeyPath), ticket, Base.readIv(ivPath)
    ));
    return new TicketDto(unbundled.sourceHash(), unbundled.sessionKey(), unbundled.sessionIV());
  }
  protected static boolean checkByteArray(
    byte[] message, String secretKeyPath, String publicKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.check(
      message, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath), Base.readIv(ivPath)
    );
  }

  protected static byte[] decryptByteArray(
    byte[] message, String secretKeyPath, String ivPath
  ) throws Exception {
    return Decrypter.decryptByteArray(message, Base.readSecretKey(secretKeyPath), Base.readIv(ivPath));
  }

  protected static byte[] encryptByteArray(
    byte[] message, String secretKeyPath, String privateKeyPath, String ivPath
  ) throws Exception {
    return Encrypter.encryptByteArray(
      message, Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath), Base.readIv(ivPath)
    );
  }
}
