package pt.ulisboa.ist.sirs.userclient.tools;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Security;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SecureDocument {
  SecretKey secretKey;
  PublicKey publicKey;
  PrivateKey privateKey;
  byte[] iv;

  public SecureDocument(String ivPath, String secretKeyPath, String publicKeyPath, String privateKeyPath)
      throws Exception {
    this.iv = Base.readIv(ivPath);
    this.secretKey = Base.readSecretKey(secretKeyPath);
    this.publicKey = Base.readPublicKey(publicKeyPath);
    this.privateKey = Base.readPrivateKey(privateKeyPath);
  }

  private SecretKey getSecretKey() {
    return secretKey;
  }

  private PublicKey getPublicKey() {
    return publicKey;
  }

  private PrivateKey getPrivateKey() {
    return privateKey;
  }

  private byte[] getIV() {
    return iv;
  }

  public void protect(String inputFile, String outputFile) {
    try {
      Utils.writeBytesToFile(
          Security.protect(Utils.readBytesFromFile(inputFile), getSecretKey(), getPrivateKey(), getIV()),
          outputFile);
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }

  public boolean check(String inputFile) {
    try {
      byte[] cryptogram = Utils.readBytesFromFile(inputFile);
      return Security.check(cryptogram, getSecretKey(), getPublicKey(), getIV());
    } catch (Exception e) {
      System.out.println(e.getMessage());
      return false;
    }
  }

  public void unprotect(String inputFile, String outputFile) {
    try {
      Utils.writeBytesToFile(
          Security.unprotect(Utils.readBytesFromFile(inputFile), getSecretKey(), getIV()),
          outputFile);
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }
}
