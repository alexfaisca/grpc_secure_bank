package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.JsonObject;
import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public final class Base {

  public interface KeyManager {
    Map<Integer, String> ivPaths = new HashMap<>();
    Map<Integer, String> secretKeyPaths = new HashMap<>();
    Map<Integer, String> publicKeyPaths = new HashMap<>();
    Map<Integer, String> privateKeyPaths = new HashMap<>();

    default String getIvPath(Integer user) {
      return ivPaths.get(user);
    }

    default String getSecretKeyPath(Integer user) {
      return secretKeyPaths.get(user);
    }

    default String getPublicKeyPath(Integer user) {
      return publicKeyPaths.get(user);
    }

    default String getPrivateKeyPath(Integer user) {
      return privateKeyPaths.get(user);
    }

    default void addIvPath(Integer user, String ivPath) {
      ivPaths.put(user, ivPath);
    }

    default void addSecretKeyPath(Integer user, String secretKeyPath) {
      secretKeyPaths.put(user, secretKeyPath);
    }

    default void addPublicKeyPath(Integer user, String publicKeyPath) {
      publicKeyPaths.put(user, publicKeyPath);
    }

    default void addPrivateKeyPath(Integer user, String publicKeyPath) {
      privateKeyPaths.put(user, publicKeyPath);
    }
  }

  public interface CryptographicCore {
    static void initializeSelfDirectory() {
      File clientDirectory = new File("resources/crypto/self/");
      if (!clientDirectory.exists())
        if (!clientDirectory.mkdirs())
          throw new RuntimeException("Could not store client key");
    }
    static String getPublicKeyPath() {
      return "resources/crypto/self/publicKey";
    }
    static String getPrivateKeyPath() {
      return "resources/crypto/self/privateKey";
    }

    default boolean check(byte[] input, String secretKeyPath, String publicKeyPath, String ivPath)
        throws Exception {
      return Security.check(input, Base.readSecretKey(secretKeyPath), Base.readPublicKey(publicKeyPath),
          Base.readIv(ivPath));
    }

    default JsonObject decrypt(byte[] input, String secretKeyPath, String ivPath)
        throws Exception {
      return Utils.deserializeJson(Security.unprotect(input, Base.readSecretKey(secretKeyPath), Base.readIv(ivPath)));
    }

    default byte[] encrypt(byte[] input, String secretKeyPath, String privateKeyPath, String ivPath)
        throws Exception {
      return Security.protect(input, Base.readSecretKey(secretKeyPath), Base.readPrivateKey(privateKeyPath),
          Base.readIv(ivPath));
    }

    final class Decrypter {
      public static boolean check(byte[] input, SecretKey secretKey, PublicKey publicKey, byte[] iv)
          throws Exception {
        return Security.check(input, secretKey, publicKey, iv);
      }

      public static JsonObject decrypt(byte[] input, SecretKey secretKey, byte[] iv)
          throws Exception {
        return Utils.deserializeJson(Security.unprotect(input, secretKey, iv));
      }
    }

    final class Encrypter {
      public static byte[] encrypt(byte[] input, SecretKey secretKey, PrivateKey privateKey, byte[] iv)
          throws Exception {
        return Security.protect(input, secretKey, privateKey, iv);
      }
    }
  }

  public static Long generateRandom(long max) {
    return (new SecureRandom()).nextLong(max);
  }

  public static byte[] intToByteArray(int value) {
    return new byte[] {
        (byte) (value >>> 24),
        (byte) (value >>> 16),
        (byte) (value >>> 8),
        (byte) value };
  }

  public static int byteArrayToInt(byte[] value) {
    return  ((value[0] & 0xFF) << 24) |
            ((value[1] & 0xFF) << 16) |
            ((value[2] & 0xFF) << 8) |
            ((value[3] & 0xFF));
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
