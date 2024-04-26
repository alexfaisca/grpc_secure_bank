package pt.ulisboa.ist.sirs.cryptology;

import pt.ulisboa.ist.sirs.cryptology.Base.AuthClient;
import pt.ulisboa.ist.sirs.dto.KeyIVPair;

import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public final class DiffieHellmanClient {
  private KeyAgreement clientKeyAgree;
  private final AuthClient crypto;
  public DiffieHellmanClient(AuthClient crypto) {
    this.crypto = crypto;
  }

  public byte[] diffieHellmanInitialize() throws NoSuchAlgorithmException, InvalidKeyException {
    KeyPairGenerator clientKeypairGen = KeyPairGenerator.getInstance(Base.DH_ALG);
    clientKeypairGen.initialize(Base.ASYMMETRIC_KEY_SIZE);
    KeyPair keyPair = clientKeypairGen.generateKeyPair();

    // Client creates and initializes his DH KeyAgreement object
    clientKeyAgree = KeyAgreement.getInstance(Base.DH_ALG);
    clientKeyAgree.init(keyPair.getPrivate());

    // Client encodes his public key, and sends it to server.
    return keyPair.getPublic().getEncoded();
  }

  public void diffieHellmanFinish(
    byte[] serverPublic, byte[] serverParams
  ) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, NoSuchPaddingException,
          InvalidAlgorithmParameterException {
    // Client uses server's public key for the first (and only) phase of his part of the DH protocol.
    KeyFactory clientKeyFac = KeyFactory.getInstance(Base.DH_ALG);
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublic);
    PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

    clientKeyAgree.doPhase(serverPubKey, true);
    // Instantiate AlgorithmParameters object from parameter encoding obtained from server
    KeyIVPair pair = Operations.generateKeyIVFromSecretAndParams(clientKeyAgree.generateSecret(), serverParams);

    crypto.initializeAuth(pair.key().getEncoded(), pair.iv());
  }
}
