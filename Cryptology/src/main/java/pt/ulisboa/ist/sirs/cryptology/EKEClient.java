package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.cryptology.Base.EKEClientManager;
import pt.ulisboa.ist.sirs.dto.EKEParams;
import pt.ulisboa.ist.sirs.dto.KeyIVPair;
import pt.ulisboa.ist.sirs.utils.Utils;
import pt.ulisboa.ist.sirs.utils.exceptions.KeyGenerationException;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public final class EKEClient {
  private KeyAgreement clientKeyAgree;
  private SecretKey ephemeralKey;
  private byte[] ephemeralIV;
  private final EKEClientManager crypto;
  public EKEClient(EKEClientManager crypto) {
    this.crypto = crypto;
  }
  public EKEParams encryptedKeyExchange() throws Exception {

    KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance(Base.DH_ALG);
    clientKeypairGen.initialize(Base.ASYMMETRIC_KEY_SIZE);
    KeyPair keyPair = clientKeypairGen.generateKeyPair();

    // Client creates and initializes her DH KeyAgreement object
    clientKeyAgree = KeyAgreement.getInstance(Base.DH_ALG);
    clientKeyAgree.init(keyPair.getPrivate());
    // Client encodes his public key, and sends it to server.
    byte[] ephemeralKeyEnc = Operations.generateSessionKey();
    ephemeralIV = Operations.generateIV(new SecureRandom().nextInt(), ephemeralKeyEnc, String.valueOf(new SecureRandom().nextDouble()));
    if (ephemeralKeyEnc == null || ephemeralIV == null)
      throw new KeyGenerationException();
    // Merge ephemeral symmetric key and iv to encrypt using server public key
    byte[] keyIVConcat = new byte[ephemeralKeyEnc.length + ephemeralIV.length];
    System.arraycopy(ephemeralKeyEnc, 0, keyIVConcat, 0, ephemeralKeyEnc.length);
    System.arraycopy(ephemeralIV, 0, keyIVConcat, ephemeralKeyEnc.length, ephemeralIV.length);
    ephemeralKey = new SecretKeySpec(ephemeralKeyEnc, Base.SYMMETRIC_ALG);
    return new EKEParams(
      Operations.encryptData(ephemeralKey, keyPair.getPublic().getEncoded(), ephemeralIV),
      Operations.encryptDataAsymmetric(Base.readPublicKey(crypto.buildPublicKeyPath()), keyIVConcat)
    );
  }

  public long finalize(
    byte[] serverParams, byte[] encryptedChallenge
  ) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    EKEParams params = Base.KeyManager.unbundleParams(Operations.decryptData(
      ephemeralKey,
      serverParams,
      ephemeralIV
    ));
    KeyFactory clientKeyFac = KeyFactory.getInstance(Base.DH_ALG);
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(params.publicKeySpecs());
    PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

    clientKeyAgree.doPhase(serverPubKey, true);
    // Instantiate AlgorithmParameters object from parameter encoding obtained from server
    KeyIVPair pair = Operations.generateKeyIVFromSecretAndParams(clientKeyAgree.generateSecret(), params.params());

    crypto.initializeSession(pair.key().getEncoded(), pair.iv());
    return Utils.byteArrayToLong(Operations.decryptData(pair.key(), encryptedChallenge, pair.iv()));
  }
}
