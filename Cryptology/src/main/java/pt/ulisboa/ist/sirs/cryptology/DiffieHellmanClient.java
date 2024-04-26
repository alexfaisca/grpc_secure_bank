package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.cryptology.Base.AuthClient;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class DiffieHellmanClient {
  private KeyAgreement clientKeyAgree;
  private final AuthClient crypto;
  public DiffieHellmanClient(AuthClient crypto) {
    this.crypto = crypto;
  }

  public byte[] diffieHellmanInitialize() throws NoSuchAlgorithmException, InvalidKeyException {
    KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance("DH");
    clientKeypairGen.initialize(2048);
    KeyPair keyPair = clientKeypairGen.generateKeyPair();

    // Client creates and initializes his DH KeyAgreement object
    clientKeyAgree = KeyAgreement.getInstance("DH");
    clientKeyAgree.init(keyPair.getPrivate());

    // Client encodes his public key, and sends it to server.
    return keyPair.getPublic().getEncoded();
  }

  public void diffieHellmanFinish(byte[] serverPublic, byte[] serverParams) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    /*
     * Client uses server's public key for the first (and only) phase
     * of his part of the DH protocol.
     */
    KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublic);
    PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

    clientKeyAgree.doPhase(serverPubKey, true);

    byte[] sharedSecret = clientKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

    // Instantiate AlgorithmParameters object from parameter encoding
    // obtained from server
    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
    aesParams.init(serverParams);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
    byte[] temp = Arrays.copyOfRange(aesParams.getEncoded(), 10, 14);
    byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

    crypto.initializeAuth(aesKey.getEncoded(), iv);
  }
}
