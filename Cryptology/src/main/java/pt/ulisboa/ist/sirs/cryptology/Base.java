package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.dto.EKEParams;
import pt.ulisboa.ist.sirs.dto.Ticket;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class Base {
  public static final int SYMMETRIC_KEY_SIZE = 32; // bytes
  public static final int IV_SIZE = SYMMETRIC_KEY_SIZE / 2; // bytes
  public static final int ASYMMETRIC_KEY_SIZE = 4096; // in bits
  public static final int SIGNATURE_SIZE = ASYMMETRIC_KEY_SIZE / 8; // asymmetric key size in bytes
  public static final int HASH_SIZE = SYMMETRIC_KEY_SIZE; // bytes
  public static final int STD_TICKET_PARAMS_SIZE = 18; // bytes
  public interface AuthClient {
    void initializeAuth(byte[] symmetricKey, byte[] iv);
  }
  public interface EKEClientManager {
    String buildPublicKeyPath();
    void initializeSession(byte[] symmetricKey, byte[] iv);
  }

  public interface KeyManager {
    static byte[] bundleTicket(String source, byte[] sessionKey, byte[] sessionIV) throws NoSuchAlgorithmException {
      byte[] result = new byte[80];
      System.arraycopy(Operations.hash(source.getBytes(StandardCharsets.UTF_8)), 0, result, 0, HASH_SIZE);
      System.arraycopy(sessionKey, 0, result, HASH_SIZE, SYMMETRIC_KEY_SIZE);
      System.arraycopy(sessionIV, 0, result, HASH_SIZE + SYMMETRIC_KEY_SIZE, IV_SIZE);
      return result;
    }
    static Ticket unbundleTicket(byte[] ticket) {
      return new Ticket(
        Arrays.copyOfRange(ticket, 0, HASH_SIZE),
        Arrays.copyOfRange(ticket, HASH_SIZE, HASH_SIZE + SYMMETRIC_KEY_SIZE),
        Arrays.copyOfRange(ticket, HASH_SIZE + SYMMETRIC_KEY_SIZE, HASH_SIZE + SYMMETRIC_KEY_SIZE + IV_SIZE)
      );
    }
    static byte[] unbundleParams(byte[] params, byte[] publicKeySpecs) {
      byte[] result = new byte[STD_TICKET_PARAMS_SIZE + publicKeySpecs.length];
      System.arraycopy(params, 0, result, 0, STD_TICKET_PARAMS_SIZE);
      System.arraycopy(publicKeySpecs, 0, result, STD_TICKET_PARAMS_SIZE, publicKeySpecs.length);
      return result;
    }
    static EKEParams unbundleParams(byte[] bundle) {
      return new EKEParams(
        Arrays.copyOfRange(bundle, 0, STD_TICKET_PARAMS_SIZE),
        Arrays.copyOfRange(bundle, STD_TICKET_PARAMS_SIZE, bundle.length)
      );
    }
  }

  public interface CryptographicCore {
    static void initializeSelfDirectory() {
      File clientDirectory = new File("resources/crypto/self/");
      if (!clientDirectory.exists())
        if (!clientDirectory.mkdirs())
          throw new RuntimeException("Could not store client key");
    }
    static String getCertPath() {
      return "resources/certificates/cert.pem";
    }
    static String getPublicKeyPath() {
      return "resources/crypto/self/publicKey";
    }
    static String getPrivateKeyPath() {
      return "resources/crypto/self/privateKey";
    }

    final class Decrypter {
      public static boolean check(byte[] input, SecretKey secretKey, PublicKey publicKey, byte[] iv)
          throws Exception {
        return Security.check(input, secretKey, publicKey, iv);
      }
      public static byte[] decryptByteArray(byte[] input, SecretKey secretKey, byte[] iv)
              throws Exception {
        return Security.unprotect(input, secretKey, iv);
      }
    }

    final class Encrypter {
      public static byte[] encryptByteArray(byte[] input, SecretKey secretKey, PrivateKey privateKey, byte[] iv)
          throws Exception {
        return Security.protect(input, secretKey, privateKey, iv);
      }
    }
  }

  public static Long generateRandom(long max) {
    return (new SecureRandom()).nextLong(max);
  }

  public static SecretKey readSecretKey(String secretKeyPath) throws Exception {
    return new SecretKeySpec(Utils.readBytesFromFile(secretKeyPath), "AES");
  }

  public static PublicKey readPublicKey(String publicKeyPath) throws Exception {
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Utils.readBytesFromFile(publicKeyPath));
    return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
  }

  public static PrivateKey readPrivateKey(String privateKeyPath) throws Exception {
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Utils.readBytesFromFile(privateKeyPath));
    return KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
  }

  public static byte[] readIv(String ivPath) throws Exception {
    return Utils.readBytesFromFile(ivPath);
  }
}
