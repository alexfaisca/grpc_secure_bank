package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.cryptology.Base.EKEClientManager;
import pt.ulisboa.ist.sirs.dto.EKEParams;
import pt.ulisboa.ist.sirs.utils.Utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class EKEClient {
  private KeyAgreement clientKeyAgree;
  private SecretKey ephemeralKey;
  private byte[] ephemeralIV;
  private final EKEClientManager crypto;
  public EKEClient(EKEClientManager crypto) {
    this.crypto = crypto;
  }
  public EKEParams encryptedKeyExchange() throws Exception {

    KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance("DH");
    clientKeypairGen.initialize(Base.ASYMMETRIC_KEY_SIZE);
    KeyPair keyPair = clientKeypairGen.generateKeyPair();

    // Client creates and initializes her DH KeyAgreement object
    clientKeyAgree = KeyAgreement.getInstance("DH");
    clientKeyAgree.init(keyPair.getPrivate());
    // Client encodes his public key, and sends it to server.
    byte[] ephemeralKeyEnc = Operations.generateSessionKey();
    ephemeralIV = Operations.generateIV(new SecureRandom().nextInt(), ephemeralKeyEnc, String.valueOf(new SecureRandom().nextDouble()));
    if (ephemeralKeyEnc == null || ephemeralIV == null)
      throw new RuntimeException("Ephemeral key generation went wrong.");
    // Merge ephemeral symmetric key and iv to encrypt using server public key
    byte[] keyIVConcat = new byte[ephemeralKeyEnc.length + ephemeralIV.length];
    System.arraycopy(ephemeralKeyEnc, 0, keyIVConcat, 0, ephemeralKeyEnc.length);
    System.arraycopy(ephemeralIV, 0, keyIVConcat, ephemeralKeyEnc.length, ephemeralIV.length);
    ephemeralKey = new SecretKeySpec(ephemeralKeyEnc, "AES");
    return new EKEParams(
      Operations.encryptData(ephemeralKey, keyPair.getPublic().getEncoded(), ephemeralIV),
      Operations.encryptDataAsymmetric(Base.readPublicKey(crypto.buildPublicKeyPath()), keyIVConcat)
    );
  }

  public long finalize(
    byte[] serverParams, byte[] encryptedChallenge
  ) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    EKEParams params = Base.KeyManager.unbundleParams(Operations.decryptData(
            ephemeralKey,
            serverParams,
            ephemeralIV
    ));
    KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(params.publicKeySpecs());
    PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

    clientKeyAgree.doPhase(serverPubKey, true);

    byte[] sharedSecret = clientKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, Base.SYMMETRIC_KEY_SIZE, "AES");

    // Instantiate AlgorithmParameters object from parameter encoding obtained from server
    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
    aesParams.init(params.params());
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
    byte[] temp = Arrays.copyOfRange(aesParams.getEncoded(), 10, 10 + Integer.BYTES);
    byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

    crypto.initializeSession(aesKey.getEncoded(), iv);
    return Utils.byteArrayToLong(Operations.decryptData(aesKey, encryptedChallenge, iv));
  }
}
