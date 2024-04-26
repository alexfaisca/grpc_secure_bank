package pt.ulisboa.ist.sirs.databaseserver.grpc.crypto;

import pt.ulisboa.ist.sirs.cryptology.Base;
import pt.ulisboa.ist.sirs.cryptology.Operations;
import pt.ulisboa.ist.sirs.databaseserver.dto.EKEExchangeParamsDto;
import pt.ulisboa.ist.sirs.databaseserver.dto.KeyParamsDto;
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
  private final AuthenticationClientCryptographicManager crypto;
  public EKEClient(AuthenticationClientCryptographicManager crypto) {
    this.crypto = crypto;
  }
  public EKEExchangeParamsDto encryptedKeyExchange() throws Exception {

    KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance("DH");
    clientKeypairGen.initialize(2048);
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
    return new EKEExchangeParamsDto(
      Operations.encryptData(ephemeralKey, keyPair.getPublic().getEncoded(), ephemeralIV),
      Operations.encryptDataAsymmetric(Base.readPublicKey(crypto.buildPublicKeyPath()), keyIVConcat)
    );
  }

  public long finalize(
    byte[] serverParams, byte[] encryptedChallenge
  ) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    KeyParamsDto params = crypto.unbundleKeyParams(ephemeralKey, serverParams, ephemeralIV);
    KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(params.keySpecs());
    PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

    clientKeyAgree.doPhase(serverPubKey, true);

    byte[] sharedSecret = clientKeyAgree.generateSecret();
    SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 32, "AES");

    // Instantiate AlgorithmParameters object from parameter encoding obtained from server
    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
    aesParams.init(params.params());
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
    byte[] temp = Arrays.copyOfRange(aesParams.getEncoded(), 10, 14);
    byte[] iv = Operations.generateIV(Utils.byteArrayToInt(temp), aesKey.getEncoded(), Utils.byteToHex(sharedSecret));

    crypto.initializeSession(aesKey.getEncoded(), iv);
    return Utils.byteArrayToLong(Operations.decryptData(aesKey, encryptedChallenge, iv));
  }
}
