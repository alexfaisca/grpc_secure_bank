package pt.tecnico.sirs.cryptology;

import java.security.*;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public final class Security {

  public static byte[] protect(byte[] message, SecretKey secretKey, PrivateKey privateKey, byte[] iv)
      throws SignatureException, InvalidKeyException, NoSuchAlgorithmException,
      InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    byte[] signature = Operations.messageSignature(privateKey, message);

    byte[] protectedDocument = new byte[signature.length + message.length];
    System.arraycopy(signature, 0, protectedDocument, 0, signature.length);
    System.arraycopy(message, 0, protectedDocument, signature.length, message.length);

    return Operations.encryptData(secretKey, protectedDocument, iv);
  }

  public static boolean check(byte[] cryptogram, SecretKey secretKey, PublicKey publicKey, byte[] iv)
      throws NoSuchPaddingException, SignatureException, NoSuchAlgorithmException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    byte[] protectedDocument = Operations.decryptData(secretKey, cryptogram, iv);
    byte[] signature = Arrays.copyOfRange(protectedDocument, 0, 256);
    byte[] message = Arrays.copyOfRange(protectedDocument, 256, protectedDocument.length);

    return Operations.messageValidation(publicKey, message, signature);
  }

  public static byte[] unprotect(byte[] cryptogram, SecretKey secretKey, byte[] iv)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    byte[] protectedDocument = Operations.decryptData(secretKey, cryptogram, iv);
    byte[] message = Arrays.copyOfRange(protectedDocument, 256, protectedDocument.length);
    byte[] document = new byte[message.length];
    System.arraycopy(message, 0, document, 0, message.length);
    return document;
  }

}
