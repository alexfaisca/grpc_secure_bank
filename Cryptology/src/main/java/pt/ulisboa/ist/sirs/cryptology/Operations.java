package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.utils.Utils;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Operations {

  public static byte[] encryptData(SecretKey secretKey, byte[] message, byte[] iv)
      throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException {
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

    return cipher.doFinal(message);
  }

  public static byte[] decryptData(SecretKey secretKey, byte[] cipherText, byte[] iv)
      throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException {
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

    return cipher.doFinal(cipherText);
  }

  public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
    final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    return messageDigest.digest(message);
  }

  public static byte[] messageSignature(PrivateKey privateKey, byte[] message)
      throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(digest);

    return signature.sign();
  }

  public static boolean messageValidation(PublicKey publicKey, byte[] message, byte[] messageSignature)
      throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);
    signature.update(digest);

    return signature.verify(messageSignature);
  }

  public static byte[] generateSessionKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(256);
      SecretKey symmetricKey = keyGenerator.generateKey();
      return symmetricKey.getEncoded();
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
    return null;
  }

  public static byte[] generateIV(Integer id, byte[] secretKey, String secret) {
    try {
      return Arrays.copyOf(
          encryptData(
              new SecretKeySpec(secretKey, "AES"),
              MessageDigest.getInstance("SHA-256").digest(secret.getBytes()),
              Arrays.copyOf(
                  MessageDigest.getInstance("SHA-256").digest(ByteBuffer.allocate(Integer.BYTES).putInt(id).array()),
                  16)),
          16);
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
    return null;
  }
}
